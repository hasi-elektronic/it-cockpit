# Hasi IT-Cockpit

**All-in-One IT Management Platform für KMU** — deeploi Alternative, made in Vaihingen/Enz.

## 🚀 Mac Kurulum (tek komut)

```bash
git clone https://github.com/hasi-elektronic/it-cockpit.git
cd it-cockpit
bash install.sh
```

D1, schema, secrets, Worker deploy, admin user — hepsi otomatik. ~2 dakika. → [KURULUM.md](./KURULUM.md)

## 🌐 Canlı URLs

- **Frontend**: https://it-cockpit.pages.dev
- **Worker API**: https://it-cockpit-api.hguencavdi.workers.dev (Mac'te deploy sonrası)

## 📦 Stack

- **Frontend**: Vue 3 (CDN) + Tailwind → Cloudflare Pages
- **Backend**: Cloudflare Workers (TypeScript)
- **DB**: Cloudflare D1 (SQLite, WEUR, multi-tenant)
- **Auth**: PBKDF2 100k + Bearer Token

## 🧩 Module (v0.1)

1. **Geräte-Inventar** — Hostname, User, Seriennummer, OS, Garantie
2. **Lizenz-Cockpit** — Software-Keys, Seats, Ablauf, Kosten
3. **Audit-Log** — DSGVO-konforme Aktion-Historie
4. **CSV Bulk Import** — 30 PC tek upload

## 🛣️ Roadmap

| Version | Inhalt |
|---|---|
| **v0.1** ✅ | Devices + Licenses + Audit + CSV Import |
| v0.1.1 | Modal'lar (UI ekleme), Mitarbeiter CRUD |
| v0.2 | Onboarding-Automation (MS365 + Google Workspace API) |
| v0.3 | Ticket-System (n8n entegrasyonu) |
| v0.4 | Cybersecurity-Modul (Policy-Compliance-Check) |
| v0.5 | Reporting-Dashboard + Mobile App |

## 💰 Preise

| Plan | Preis | Inhalt |
|---|---|---|
| Pilot | €0 / 6 Monat | İlk 10 KMU (Vaihingen/Enz), Testimonial karşılığı |
| Starter | €15/Gerät/ay + €290 Setup | <25 Gerät, Email-Support |
| Pro | €25/Gerät/ay + €490 Setup | <100 Gerät, Telefon + Vor-Ort |
| Enterprise | Anfrage | Multi-Standort, SLA, Custom |

## 🎯 Pilot

- **Manfred Sickinger GmbH** — 30 PC (Test-tenant ⭐)
- Phase 1 (Q2 2026): Geräte + Lizenzen
- Phase 2 (Q3 2026): Onboarding + Ticket

## 📁 Repo-Struktur

```
it-cockpit/
├── frontend/           Vue 3 SPA (landing + login + dashboard)
│   ├── index.html
│   ├── _headers
│   ├── _redirects
│   └── csv-template.csv
├── worker/             Cloudflare Worker API
│   ├── src/index.ts    (303 satır, 8 endpoint)
│   ├── wrangler.toml
│   └── package.json
├── db/
│   └── schema.sql      (6 tablo + seed)
├── docs/
│   └── SETUP.md        (manuel kurulum)
├── install.sh          ⭐ Tek-komutluk kurulum
├── KURULUM.md          Kurulum kılavuzu (Türkçe)
└── README.md
```

---
© 2026 **Hasi Elektronic** · Hamdi Güncavdi · Vaihingen/Enz
