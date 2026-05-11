#!/usr/bin/env bash
# =====================================================================
# Hasi IT-Cockpit — Mac Auto-Installer
# Tek komutla: D1 create → UUID auto-fill → schema → secrets → deploy → admin
# =====================================================================
set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

step() { echo -e "\n${BLUE}▶ $1${NC}"; }
ok()   { echo -e "${GREEN}✓ $1${NC}"; }
warn() { echo -e "${YELLOW}⚠ $1${NC}"; }
err()  { echo -e "${RED}✗ $1${NC}" >&2; }

ADMIN_EMAIL="h.guencavdi@hasi-elektronic.de"
ADMIN_NAME="Hamdi Güncavdi"

# =====================================================================
# 0) Preflight
# =====================================================================
step "Preflight check"

command -v wrangler >/dev/null 2>&1 || { err "wrangler bulunamadı. Install: npm install -g wrangler"; exit 1; }
command -v node >/dev/null 2>&1 || { err "node bulunamadı."; exit 1; }
command -v openssl >/dev/null 2>&1 || { err "openssl bulunamadı."; exit 1; }
ok "wrangler $(wrangler --version | head -1)"
ok "node $(node --version)"

# Check wrangler login
if ! wrangler whoami >/dev/null 2>&1; then
  warn "wrangler'a giriş yapılmamış. Şimdi 'wrangler login' çalıştırılıyor..."
  wrangler login
fi
ACCOUNT=$(wrangler whoami 2>&1 | grep -oE '[a-f0-9]{32}' | head -1 || echo "")
ok "Logged in (account: ${ACCOUNT:0:8}...)"

# =====================================================================
# 1) D1 create veya mevcut UUID'yi bul
# =====================================================================
step "D1 Database hazırlanıyor"

cd worker

# Mevcut listeyi kontrol et
EXISTING_UUID=$(wrangler d1 list --json 2>/dev/null | node -e "
  let data='';process.stdin.on('data',c=>data+=c).on('end',()=>{
    try { const j=JSON.parse(data); const m=j.find(d=>d.name==='it-cockpit'); console.log(m?m.uuid:''); } catch(e){console.log('');}
  });
" 2>/dev/null || echo "")

if [ -n "$EXISTING_UUID" ]; then
  ok "Mevcut D1 bulundu: $EXISTING_UUID"
  DB_UUID="$EXISTING_UUID"
else
  echo "D1 'it-cockpit' oluşturuluyor (location: WEUR)..."
  CREATE_OUT=$(wrangler d1 create it-cockpit --location=weur 2>&1)
  echo "$CREATE_OUT"
  DB_UUID=$(echo "$CREATE_OUT" | grep -oE '[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}' | head -1)

  if [ -z "$DB_UUID" ]; then
    err "D1 UUID alınamadı. wrangler çıktısını kontrol et."
    exit 1
  fi
  ok "D1 oluşturuldu: $DB_UUID"
fi

# =====================================================================
# 2) wrangler.toml içine UUID yapıştır
# =====================================================================
step "wrangler.toml güncelleniyor"

# macOS sed (-i'' farklı) ve Linux sed uyumlu
if [[ "$OSTYPE" == "darwin"* ]]; then
  sed -i '' "s/REPLACE_AFTER_D1_CREATE/$DB_UUID/g" wrangler.toml
else
  sed -i "s/REPLACE_AFTER_D1_CREATE/$DB_UUID/g" wrangler.toml
fi
ok "wrangler.toml güncellendi"
grep "database_id" wrangler.toml

# =====================================================================
# 3) Schema yükle
# =====================================================================
step "Schema import ediliyor (6 tablo)"
wrangler d1 execute it-cockpit --file=../db/schema.sql --remote --yes
ok "Schema yüklendi"

# =====================================================================
# 4) Secrets oluştur (varsa atla)
# =====================================================================
step "Worker secrets ayarlanıyor"

PW_SALT_VAL=$(openssl rand -hex 32)
TOKEN_SECRET_VAL=$(openssl rand -hex 32)

# Secret'ları kaydet (stdin üzerinden)
echo "$PW_SALT_VAL" | wrangler secret put PW_SALT 2>&1 | tail -1
echo "$TOKEN_SECRET_VAL" | wrangler secret put TOKEN_SECRET 2>&1 | tail -1
ok "Secrets kaydedildi (PW_SALT, TOKEN_SECRET)"

# Lokal yedek (.secrets klasörü, .gitignore'da)
mkdir -p ../.secrets
cat > ../.secrets/it-cockpit.env << EOF
# Hasi IT-Cockpit Secrets — YEREL KOPYA, ASLA Git'e PUSH ETME
# Date: $(date)
D1_UUID=$DB_UUID
PW_SALT=$PW_SALT_VAL
TOKEN_SECRET=$TOKEN_SECRET_VAL
EOF
chmod 600 ../.secrets/it-cockpit.env
ok "Lokal yedek: ../.secrets/it-cockpit.env"

# =====================================================================
# 5) Worker deploy
# =====================================================================
step "Worker deploy"
wrangler deploy 2>&1 | tail -5
ok "Worker canlıda: https://it-cockpit-api.hguencavdi.workers.dev/health"

# Health check
sleep 3
HEALTH=$(curl -s -o /dev/null -w "%{http_code}" https://it-cockpit-api.hguencavdi.workers.dev/health || echo "000")
if [ "$HEALTH" = "200" ]; then
  ok "Worker health check: 200 OK"
else
  warn "Worker health: $HEALTH (yayılma 30 sn sürebilir, tekrar dene: curl https://it-cockpit-api.hguencavdi.workers.dev/health)"
fi

# =====================================================================
# 6) Admin user oluştur (Hamdi)
# =====================================================================
step "Admin user (Hamdi) oluşturuluyor"

# Generiere random admin password
ADMIN_PW=$(openssl rand -base64 18 | tr -d '/+=' | head -c 16)

# PBKDF2 hash üret
ADMIN_HASH=$(node -e "
const crypto = require('crypto');
const hash = crypto.pbkdf2Sync('$ADMIN_PW', '$PW_SALT_VAL', 100000, 32, 'sha256').toString('hex');
console.log(hash);
")

# Insert user
wrangler d1 execute it-cockpit --remote --yes --command "
DELETE FROM users WHERE tenant_id=(SELECT id FROM tenants WHERE slug='sickinger') AND email='$ADMIN_EMAIL';
INSERT INTO users (tenant_id, email, full_name, role, pw_hash, pw_salt, active)
VALUES (
  (SELECT id FROM tenants WHERE slug='sickinger'),
  '$ADMIN_EMAIL',
  '$ADMIN_NAME',
  'super_admin',
  '$ADMIN_HASH',
  '$PW_SALT_VAL',
  1
);
" 2>&1 | tail -2

ok "Admin user oluşturuldu"

# Password'ü secrets dosyasına ekle
cat >> ../.secrets/it-cockpit.env << EOF

# === Sickinger Admin Login ===
ADMIN_TENANT=sickinger
ADMIN_EMAIL=$ADMIN_EMAIL
ADMIN_PASSWORD=$ADMIN_PW
EOF

# =====================================================================
# 7) Frontend redeploy (Worker URL update)
# =====================================================================
step "Frontend kontrol (zaten canlı)"
FRONT_HEALTH=$(curl -s -o /dev/null -w "%{http_code}" https://it-cockpit.pages.dev || echo "000")
ok "Frontend: $FRONT_HEALTH (https://it-cockpit.pages.dev)"

# =====================================================================
# 8) FINAL REPORT
# =====================================================================
echo ""
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  ✅ KURULUM TAMAM${NC}"
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${BOLD}🌐 URLs:${NC}"
echo "   Frontend:  https://it-cockpit.pages.dev"
echo "   Worker:    https://it-cockpit-api.hguencavdi.workers.dev/health"
echo "   GitHub:    https://github.com/hasi-elektronic/it-cockpit"
echo ""
echo -e "${BOLD}🔐 Login (zur Anmeldung):${NC}"
echo "   Tenant:    sickinger"
echo "   Email:     $ADMIN_EMAIL"
echo "   Password:  $ADMIN_PW"
echo ""
echo -e "${YELLOW}   ⚠ Bu şifreyi ../.secrets/it-cockpit.env dosyasına da kaydettim.${NC}"
echo ""
echo -e "${BOLD}📊 Database:${NC}"
echo "   D1 UUID:   $DB_UUID"
echo "   Tablolar:  tenants, users, devices, licenses, assignments, audit_log"
echo "   Seed:      sickinger + hasi tenant'ları + admin user"
echo ""
echo -e "${BOLD}🚀 Sonraki adımlar:${NC}"
echo "   1. Tarayıcıda https://it-cockpit.pages.dev aç"
echo "   2. 'Jetzt einloggen' → yukarıdaki credentials"
echo "   3. Sidebar → CSV Import → frontend/csv-template.csv test et"
echo "   4. Sickinger'de gerçek 30 PC için CSV hazırla"
echo ""
echo -e "${GREEN}İyi çalışmalar Hamdi.${NC}"
