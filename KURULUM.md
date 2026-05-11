# 🚀 Kurulum — Mac Terminal (2 dakika)

## Tek komutluk kurulum

```bash
git clone https://github.com/hasi-elektronic/it-cockpit.git
cd it-cockpit
bash install.sh
```

Script şunları otomatik yapar:
1. ✓ Cloudflare D1 database oluşturur (it-cockpit, WEUR)
2. ✓ UUID'yi `wrangler.toml`'a otomatik yapıştırır
3. ✓ Schema yükler (6 tablo + Sickinger seed)
4. ✓ Random PW_SALT + TOKEN_SECRET üretip Worker'a kaydeder
5. ✓ Worker deploy eder
6. ✓ Sickinger için admin user oluşturur (Hamdi)
7. ✓ Random şifre oluşturur ve `.secrets/it-cockpit.env`'e kaydeder
8. ✓ Health check yapar

**Çıktıda login bilgileri tertemiz yazılır** — kopyala, browser'da aç, giriş yap.

---

## Ön koşullar

- `wrangler` kurulu: `npm install -g wrangler`
- `wrangler login` (script otomatik tetikler eğer yapılmamışsa)
- `node` + `openssl` (Mac'te zaten var)

---

## Sorun çözme

| Hata | Çözüm |
|---|---|
| `wrangler: command not found` | `npm install -g wrangler` |
| `Authentication error` | `wrangler login` (browser açar, Cloudflare hesabınla giriş) |
| `D1 already exists` | Script mevcudu kullanır, sorun değil |
| `Worker health: 522` | 30 sn bekle, tekrar test et: `curl https://it-cockpit-api.hguencavdi.workers.dev/health` |
| Login sayfasında "Login fehlgeschlagen" | `.secrets/it-cockpit.env` dosyasındaki şifreyi tekrar kontrol et |

---

## Manuel kurulum (script çalışmazsa)

`docs/SETUP.md`'ye bak — adım adım komutlar.
