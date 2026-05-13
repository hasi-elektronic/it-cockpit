// ============================================================
// D1 Backup (Security Layer 3/8)
//
// Cron: daily at 03:00 UTC
//   1. Fetch list of all user tables from sqlite_master
//   2. For each table: dump as INSERT statements
//   3. Compose a .sql file with schema + data
//   4. Write to R2: backups/YYYY-MM-DD/db.sql + manifest.json
//   5. Prune backups older than 30 days
//
// Restore (manual ops):
//   wrangler r2 object get hasi-agent-binaries/backups/2026-05-13/db.sql > restore.sql
//   wrangler d1 execute it-cockpit --remote --file=restore.sql
//
// Size budget: 19 tables * (avg 200 rows * 500 bytes) ~= 2 MB / day uncompressed.
// 30 days = 60 MB — well within R2 free tier (10 GB).
// ============================================================

export interface BackupResult {
  ok: boolean;
  date: string;
  bytes: number;
  table_count: number;
  row_count: number;
  duration_ms: number;
  pruned: number;
  error?: string;
}

const SQL_INJECT_HEADER = `-- Hasi IT-Cockpit D1 Backup
-- Generated: __TIMESTAMP__
-- WARNING: Restore on an EMPTY database. INSERT will fail on PRIMARY KEY conflicts.

PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;

`;

const SQL_FOOTER = `
COMMIT;
PRAGMA foreign_keys=ON;
`;

/** Escape a value for SQL INSERT. */
function sqlValue(v: any): string {
  if (v === null || v === undefined) return 'NULL';
  if (typeof v === 'number') return Number.isFinite(v) ? String(v) : 'NULL';
  if (typeof v === 'boolean') return v ? '1' : '0';
  // String: escape single quotes
  const s = String(v).replace(/'/g, "''");
  return `'${s}'`;
}

export async function runDailyBackup(db: D1Database, bucket: R2Bucket): Promise<BackupResult> {
  const t0 = Date.now();
  const dateIso = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
  const result: BackupResult = {
    ok: false, date: dateIso, bytes: 0, table_count: 0, row_count: 0,
    duration_ms: 0, pruned: 0,
  };

  try {
    // 1. List user tables (skip sqlite_*, _cf_*, d1_*)
    const tablesQ = await db.prepare(
      `SELECT name, sql FROM sqlite_master
       WHERE type='table'
         AND name NOT LIKE 'sqlite_%'
         AND name NOT LIKE '_cf_%'
         AND name NOT LIKE 'd1_%'
       ORDER BY name`
    ).all<{ name: string; sql: string }>();
    const tables = tablesQ.results || [];
    result.table_count = tables.length;

    // 2. Build SQL dump in memory
    const parts: string[] = [SQL_INJECT_HEADER.replace('__TIMESTAMP__', new Date().toISOString())];

    // Schema first (DDL)
    parts.push('-- Schema ----------------------------------------\n');
    for (const t of tables) {
      parts.push(`-- Table: ${t.name}\n`);
      // Include DROP for idempotent restore (commented out for safety)
      parts.push(`-- DROP TABLE IF EXISTS ${t.name};\n`);
      parts.push(`${t.sql};\n\n`);
    }

    // Indexes
    const idxQ = await db.prepare(
      `SELECT name, sql FROM sqlite_master
       WHERE type='index' AND sql IS NOT NULL
         AND name NOT LIKE 'sqlite_%'
       ORDER BY name`
    ).all<{ name: string; sql: string }>();
    parts.push('-- Indexes ---------------------------------------\n');
    for (const idx of (idxQ.results || [])) {
      parts.push(`${idx.sql};\n`);
    }
    parts.push('\n');

    // Data (INSERT statements per table)
    parts.push('-- Data ------------------------------------------\n');
    for (const t of tables) {
      // Get column list
      const colsQ = await db.prepare(`PRAGMA table_info(${t.name})`).all<{ name: string }>();
      const cols = (colsQ.results || []).map((c) => c.name);
      if (cols.length === 0) continue;

      const colList = cols.map((c) => `"${c}"`).join(', ');

      // Stream rows (D1 has 1000 row limit per query — paginate)
      let offset = 0;
      const pageSize = 500;
      let tableRowCount = 0;
      while (true) {
        const rowsQ = await db.prepare(
          `SELECT ${colList} FROM ${t.name} LIMIT ? OFFSET ?`
        ).bind(pageSize, offset).all<Record<string, any>>();
        const rows = rowsQ.results || [];
        if (rows.length === 0) break;

        for (const row of rows) {
          const values = cols.map((c) => sqlValue(row[c])).join(', ');
          parts.push(`INSERT INTO ${t.name} (${colList}) VALUES (${values});\n`);
          tableRowCount++;
        }

        if (rows.length < pageSize) break;
        offset += pageSize;
      }
      result.row_count += tableRowCount;
      parts.push(`-- ${tableRowCount} rows in ${t.name}\n\n`);
    }

    parts.push(SQL_FOOTER);

    const sqlText = parts.join('');
    result.bytes = new TextEncoder().encode(sqlText).length;

    // 3. Write to R2
    const sqlKey = `backups/${dateIso}/db.sql`;
    await bucket.put(sqlKey, sqlText, {
      httpMetadata: {
        contentType: 'application/sql; charset=utf-8',
        cacheControl: 'private, no-cache',
      },
      customMetadata: {
        'generated-at': new Date().toISOString(),
        'table-count': String(result.table_count),
        'row-count': String(result.row_count),
      },
    });

    // Manifest (for easy listing / health check)
    const manifest = {
      date: dateIso,
      generated_at: new Date().toISOString(),
      bytes: result.bytes,
      table_count: result.table_count,
      row_count: result.row_count,
      tables: tables.map((t) => t.name),
    };
    await bucket.put(`backups/${dateIso}/manifest.json`, JSON.stringify(manifest, null, 2), {
      httpMetadata: { contentType: 'application/json' },
    });

    // 4. Prune backups older than 30 days
    const cutoff = new Date(Date.now() - 30 * 86400 * 1000);
    const cutoffIso = cutoff.toISOString().slice(0, 10);

    let pruned = 0;
    let cursor: string | undefined = undefined;
    do {
      const listing: R2Objects = await bucket.list({ prefix: 'backups/', limit: 1000, cursor });
      for (const obj of listing.objects) {
        // backups/YYYY-MM-DD/...
        const m = obj.key.match(/^backups\/(\d{4}-\d{2}-\d{2})\//);
        if (!m) continue;
        if (m[1] < cutoffIso) {
          await bucket.delete(obj.key);
          pruned++;
        }
      }
      cursor = listing.truncated ? listing.cursor : undefined;
    } while (cursor);
    result.pruned = pruned;

    result.ok = true;
  } catch (e: any) {
    result.error = e.message || String(e);
    result.ok = false;
  }

  result.duration_ms = Date.now() - t0;
  return result;
}
