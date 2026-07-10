# Hasi Social Media Status

Stand: 2026-07-08, Europe/Berlin

## Neue Ausrichtung

Hasi Social Media wird stärker auf Web-Apps, iOS Apps, Android Apps, Automatisierung und digitale Lösungen für lokale Firmen ausgerichtet.

## Morgenroutine

| Uhrzeit | Inhalt | Status |
|---|---|---|
| 08:00 | Karussell / Tagespost | automatisch veröffentlichen |
| 08:30 | Reel | automatisch veröffentlichen |
| 09:00 | Story Vorbereitung | publish-ready vorbereiten, nicht automatisch veröffentlichen |

## Heute

| Kanal | Status | Thema | Slug | Instagram ID |
|---|---|---|---|---|
| Karussell | veröffentlicht | Hasi Safe Stick | `hasi-safe-stick-2026-07-08` | `18060291389739396` |
| Karussell | veröffentlicht | PC-Reparatur | `pc-reparatur-2026-07-08` | `17979586548058524` |
| Story | geplant | Vorbereitung um 09:00 | - | - |
| Reel | aktiviert | täglich 08:30 | - | - |

## Automationen

| Automation | Status | Zeit | Workspace |
|---|---|---|---|
| Hasi Instagram Tagespost | ACTIVE | täglich 08:00 | `/Users/hguencavdi/Desktop/it-cockpit` |
| Hasi Instagram Reels Tagespost | ACTIVE | täglich 08:30 | `/Users/hguencavdi/Desktop/it-cockpit` |
| Hasi Instagram Story Vorbereitung | ACTIVE | täglich 09:00 | `/Users/hguencavdi/Desktop/it-cockpit` |

## So siehst du es selbst

Starte das lokale Control Center:

```bash
cd /Users/hguencavdi/Desktop/it-cockpit/instagram-control-center
npm start
```

Dann Browser öffnen:

```text
http://localhost:8787
```

Dort siehst du:

- Instagram API Status
- Publish-ready Manifeste
- Carousel/Reel/Story Dateien
- URL Checks gegen Cloudflare R2
- Publish-Logs
- Automationsstatus

## Wichtige Regel

Nicht jeden fertigen Inhalt sofort erneut publishen. Bei Story/Reel/Carousel immer zuerst im Control Center oder in dieser Statusdatei prüfen, ob der Slug schon eine Instagram ID hat.
