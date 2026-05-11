# Hasi IT-Cockpit — Setup (Mac Terminal)

Bu doküman: GitHub'dan kodu çek → CF D1 oluştur → Schema import → Worker secrets + deploy → İlk admin user.

## Voraussetzung
- Wrangler installiert: `npm install -g wrangler`
- Cloudflare auth: `wrangler login` (browser açar)
- Repo klonlu: `git clone https://github.com/hasi-elektronic/it-cockpit.git && cd it-cockpit`

---

## Schritt 1: D1 Database oluştur

```bash
wrangler d1 create it-cockpit
```

Çıktı:
```
✅ Successfully created DB 'it-cockpit'
[[d1_databases]]
binding = "DB"
database_name = "it-cockpit"
database_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"   ← bunu kopyala
```

**database_id'yi `worker/wrangler.toml`'da `REPLACE_AFTER_D1_CREATE` ile değiştir.**

---

## Schritt 2: Schema import et

```bash
cd worker
wrangler d1 execute it-cockpit --file=../db/schema.sql --remote
```

Bekleniyor: `🚣 Executed 12+ queries in X.XXs · 6 tables, 2 tenants`

---

## Schritt 3: Worker Secrets

```bash
# Random salt + token secret oluştur (öneri):
openssl rand -hex 32   # → PW_SALT
openssl rand -hex 32   # → TOKEN_SECRET

# Worker'a yükle:
wrangler secret put PW_SALT
# (paste random hex)

wrangler secret put TOKEN_SECRET
# (paste random hex)
```

---

## Schritt 4: Admin user oluştur (Hamdi'nin login bilgisi)

Önce Worker'ı 1 kere deploy et ki secret'lar bağlansın:

```bash
wrangler deploy
```

Sonra Hamdi'nin admin user'ını schema'ya ekle. Şu komutla Node REPL ile PBKDF2 hash üret:

```bash
node -e "
const crypto = require('crypto');
const password = 'HasiCockpit2026!';
const salt = process.env.PW_SALT || '<paste-PW_SALT-here>';
const hash = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256').toString('hex');
console.log('PW_HASH:', hash);
"
```

Sonra D1'e Hamdi'yi ekle:

```bash
wrangler d1 execute it-cockpit --remote --command \
  "INSERT INTO users (tenant_id, email, full_name, role, pw_hash, pw_salt, active)
   VALUES (
     (SELECT id FROM tenants WHERE slug='sickinger'),
     'h.guencavdi@hasi-elektronic.de',
     'Hamdi Güncavdi',
     'super_admin',
     '<PASTE_HASH_FROM_NODE_COMMAND>',
     '<PASTE_SAME_PW_SALT>',
     1
   );"
```

---

## Schritt 5: Frontend Deploy

```bash
cd ../frontend
# Keby token (Pages için güvenilir)
CLOUDFLARE_API_TOKEN=<CF_API_TOKEN_KEBY> \
  wrangler pages deploy . --project-name=it-cockpit --branch=main --commit-dirty=true
```

Sonuç:
- Worker API: `https://it-cockpit-api.hguencavdi.workers.dev/health`
- Frontend: `https://it-cockpit.pages.dev`

---

## Schritt 6: Test

1. Browser → `https://it-cockpit.pages.dev`
2. "Jetzt einloggen" → Tenant: `sickinger` · Email: `h.guencavdi@hasi-elektronic.de` · Passwort: `HasiCockpit2026!`
3. Dashboard yüklenmeli, 0 Geräte gösterir
4. Sidebar → "CSV Import" → `frontend/csv-template.csv` test et (3 örnek satır)
5. Sidebar → "Geräte" → 3 cihaz listelenir ✓

---

## Schritt 7: Sickinger gerçek verisi

Sickinger'de senin masandan:

1. **CSV hazırla** (Excel'de):
   - Stütun adları: `hostname,device_type,manufacturer,model,serial_number,os,location,assigned_email,warranty_until,status`
   - 30 PC'yi doldur
   - UTF-8 olarak kaydet

2. **Import et** (Dashboard → CSV Import)

3. **Verifikasyon**:
   - Übersicht: "30 Geräte aktiv" göstermeli
   - Garantie-Warnungen otomatik tespit eder (60 günden az)

---

## Sorun çözme

| Hata | Çözüm |
|---|---|
| `wrangler: command not found` | `npm install -g wrangler` |
| Worker deploy 401 | `wrangler login` tekrar |
| CSV import 401 | Token süresi geçti, browser'da çıkış yap, tekrar gir |
| Frontend 404 | `pages deploy . --project-name=it-cockpit` çalıştırdın mı? |
| Login fehlgeschlagen | Hash + salt aynı `PW_SALT` ile mi üretildi? |

---

## Sonraki adım (v0.2)

- Modal: Gerät hinzufügen UI (şu an sadece CSV)
- License Modal
- Mitarbeiter (Users) CRUD page
- Audit-Log view
- Garantie-Warn-Email (Resend)
- Custom domain `it-cockpit.hasi-elektronic.de`
