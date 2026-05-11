# Hasi IT-Cockpit

**All-in-One IT Management Platform für KMU** — deeploi Alternative, made in Vaihingen/Enz.

## Stack
- **Frontend**: Vue 3 (CDN) + Vite-less, single-page → Cloudflare Pages
- **Backend**: Cloudflare Workers (TypeScript, modular)
- **DB**: Cloudflare D1 (SQLite, EU-WEUR, multi-tenant)
- **Storage**: R2 (Garantie-PDFs, License-Dokumente)
- **Auth**: PBKDF2 100k iterations + Bearer Token

## Module (v0.1)
1. **Geräte-Inventar** — Hostname, User, Seriennummer, OS, Garantie
2. **Lizenz-Cockpit** — Software-Keys, Seats, Ablauf, Kosten
3. **Audit-Log** — DSGVO-konforme Aktion-Historie

## Geplant (v0.2+)
- Onboarding-Automation (MS365 + Google Workspace API)
- Ticket-System (n8n-Integration)
- Cybersecurity-Modul (Policy-Compliance-Check)

## Pilot
- **Manfred Sickinger GmbH** — 30 PC, Multi-Standort
- Phase 1 (Q1/Q2 2026): Geräte + Lizenzen
- Phase 2 (Q3 2026): Onboarding + Ticket

## URL
- Production: https://it-cockpit.pages.dev
- Custom: https://it-cockpit.hasi-elektronic.de (geplant)

## Setup
Siehe `docs/SETUP.md`.

---
© 2026 Hasi Elektronic · Hamdi Güncavdi
