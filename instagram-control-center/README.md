# Hasi Content Cockpit

Steuerzentrum fuer Social-Media-Inhalte, Kundenprofile und Hasi Instagram Automationen.

## Cloudflare Pages

Projekt:

```text
hasi-content-cockpit
```

Build und Deploy:

```bash
cd /Users/hguencavdi/Desktop/it-cockpit/instagram-control-center
node build-cloudflare.mjs
wrangler pages deploy dist --project-name hasi-content-cockpit --commit-dirty=true
```

Secrets in Cloudflare Pages:

```text
COCKPIT_EMAIL
COCKPIT_PASSWORD oder COCKPIT_PASSWORD_HASH
SESSION_SECRET
```

Wichtig: Secret-Werte werden nicht ins Repository geschrieben.

## Start

```bash
cd /Users/hguencavdi/Desktop/it-cockpit/instagram-control-center
npm start
```

Danach im Browser oeffnen:

```text
http://localhost:8787
```

## Funktionen

- Instagram API Status pruefen
- Carousel, Reel und Story Manifeste anzeigen
- Cloudflare R2 URLs per HEAD pruefen
- Publish-ready Content anzeigen
- Carousel/Reel/Story manuell veroeffentlichen
- Aktive Codex Automationen anzeigen
- 14-Tage Content-Plan anzeigen
- Publish-Logs lokal speichern

## Sicherheit

- Instagram Token wird aus `instagram-karussells/tools/.env` gelesen.
- Token wird nicht in UI oder Logs ausgegeben.
- Lokal senden Publish-Buttons direkt an Instagram. Doppelte Veroeffentlichungen sind moeglich, wenn derselbe Manifest erneut gepublished wird.
- In Cloudflare Pages ist Publish bewusst deaktiviert. Cloud-Panel zeigt Status, Plan, Vorschau und Inhalte; echte Publish-Aktionen bleiben lokal, bis Instagram-Secrets sauber serverseitig angebunden sind.
