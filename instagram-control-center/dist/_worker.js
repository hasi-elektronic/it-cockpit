const SESSION_COOKIE = "hasi_cockpit_session";
const SESSION_TTL_SECONDS = 60 * 60 * 12;
const LOGIN_HTML = "<!doctype html>\n<html lang=\"de\">\n  <head>\n    <meta charset=\"utf-8\" />\n    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\n    <title>Hasi Social Media Login</title>\n    <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\" />\n    <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin />\n    <link href=\"https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700;800&display=swap\" rel=\"stylesheet\" />\n    <style>\n      :root {\n        --blue: #3abadf;\n        --ink: #0d1b2a;\n        --muted: #667085;\n        --line: #d8eef5;\n        --orange: #ff6b00;\n      }\n      * { box-sizing: border-box; }\n      body {\n        min-height: 100vh;\n        margin: 0;\n        display: grid;\n        place-items: center;\n        padding: 24px;\n        font-family: \"Space Grotesk\", system-ui, sans-serif;\n        color: var(--ink);\n        background:\n          radial-gradient(circle at 78% 20%, rgba(58, 186, 223, .24), transparent 28%),\n          linear-gradient(145deg, #081522 0%, #0d1b2a 45%, #1a5f75 100%);\n      }\n      .shell {\n        width: min(980px, 100%);\n        display: grid;\n        grid-template-columns: 1.1fr .9fr;\n        overflow: hidden;\n        border-radius: 12px;\n        background: #fff;\n        box-shadow: 0 30px 90px rgba(0, 0, 0, .36);\n      }\n      .intro {\n        padding: 42px;\n        color: #fff;\n        background:\n          radial-gradient(circle at 88% 86%, rgba(255,255,255,.17), transparent 30%),\n          linear-gradient(155deg, #0d1b2a, #3abadf);\n      }\n      .brand {\n        display: flex;\n        align-items: center;\n        gap: 14px;\n        margin-bottom: 54px;\n      }\n      .logo {\n        width: 64px;\n        height: 64px;\n        border-radius: 14px;\n        background: #fff;\n        padding: 9px;\n        object-fit: contain;\n      }\n      h1 {\n        margin: 0;\n        font-size: 42px;\n        line-height: 1;\n        letter-spacing: 0;\n      }\n      .intro p {\n        max-width: 460px;\n        color: rgba(255,255,255,.82);\n        font-size: 17px;\n        line-height: 1.45;\n      }\n      .chips {\n        display: flex;\n        flex-wrap: wrap;\n        gap: 9px;\n        margin-top: 28px;\n      }\n      .chip {\n        padding: 8px 11px;\n        border-radius: 999px;\n        background: rgba(255,255,255,.13);\n        border: 1px solid rgba(255,255,255,.18);\n        font-size: 12px;\n        font-weight: 800;\n      }\n      .login {\n        padding: 42px;\n      }\n      .login h2 {\n        margin: 0 0 8px;\n        font-size: 28px;\n      }\n      .login p {\n        margin: 0 0 26px;\n        color: var(--muted);\n        line-height: 1.45;\n      }\n      label {\n        display: block;\n        margin: 16px 0 7px;\n        color: #344054;\n        font-size: 13px;\n        font-weight: 800;\n      }\n      input {\n        width: 100%;\n        height: 48px;\n        border: 1px solid var(--line);\n        border-radius: 8px;\n        padding: 0 13px;\n        font: inherit;\n        outline: none;\n      }\n      input:focus {\n        border-color: var(--blue);\n        box-shadow: 0 0 0 4px rgba(58, 186, 223, .14);\n      }\n      button {\n        width: 100%;\n        height: 50px;\n        margin-top: 22px;\n        border: 0;\n        border-radius: 8px;\n        background: var(--orange);\n        color: #fff;\n        font: inherit;\n        font-weight: 900;\n        cursor: pointer;\n      }\n      .error {\n        min-height: 20px;\n        margin-top: 14px;\n        color: #b42318;\n        font-size: 13px;\n        font-weight: 700;\n      }\n      .small {\n        margin-top: 24px;\n        color: var(--muted);\n        font-size: 12px;\n      }\n      @media (max-width: 820px) {\n        .shell { grid-template-columns: 1fr; }\n        .intro, .login { padding: 28px; }\n      }\n    </style>\n  </head>\n  <body>\n    <main class=\"shell\">\n      <section class=\"intro\">\n        <div class=\"brand\">\n          <img class=\"logo\" src=\"/hasi-logo.png\" alt=\"Hasi Elektronic\" />\n          <div>\n            <strong>Hasi Elektronic</strong><br />\n            <span>Hasi Social Media</span>\n          </div>\n        </div>\n        <h1>Hasi Social<br />Media</h1>\n        <p>Beitraege, Storys und Reels planen, pruefen und freigeben.</p>\n        <div class=\"chips\">\n          <span class=\"chip\">Web-App</span>\n          <span class=\"chip\">iOS</span>\n          <span class=\"chip\">Android</span>\n          <span class=\"chip\">Automatisierung</span>\n        </div>\n      </section>\n      <section class=\"login\">\n        <h2>Anmelden</h2>\n        <p>Bitte mit dem Hasi Zugang anmelden, bevor die Social-Media-Zentrale geoeffnet wird.</p>\n        <form id=\"loginForm\">\n          <label for=\"email\">E-Mail</label>\n          <input id=\"email\" name=\"email\" type=\"email\" autocomplete=\"username\" required />\n          <label for=\"password\">Passwort</label>\n          <input id=\"password\" name=\"password\" type=\"password\" autocomplete=\"current-password\" required />\n          <button type=\"submit\">Hasi Social Media oeffnen</button>\n          <div class=\"error\" id=\"error\"></div>\n        </form>\n        <div class=\"small\">Geschuetzter Bereich fuer Social-Media-Kunden.</div>\n      </section>\n    </main>\n    <script>\n      document.querySelector(\"#loginForm\").addEventListener(\"submit\", async (event) => {\n        event.preventDefault();\n        const error = document.querySelector(\"#error\");\n        error.textContent = \"\";\n        const body = {\n          email: document.querySelector(\"#email\").value,\n          password: document.querySelector(\"#password\").value,\n        };\n        const response = await fetch(\"/api/login\", {\n          method: \"POST\",\n          headers: { \"Content-Type\": \"application/json\" },\n          body: JSON.stringify(body),\n        });\n        if (response.ok) {\n          const next = new URLSearchParams(window.location.search).get(\"next\") || \"/\";\n          window.location.href = next.startsWith(\"/\") ? next : \"/\";\n          return;\n        }\n        error.textContent = \"Login fehlgeschlagen. Bitte Zugangsdaten pruefen.\";\n      });\n    </script>\n  </body>\n</html>\n";
const ADMIN_HTML = "<!doctype html>\n<html lang=\"de\">\n  <head>\n    <meta charset=\"utf-8\" />\n    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\n    <title>Hasi Social Media Admin</title>\n    <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\" />\n    <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin />\n    <link href=\"https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700;800&display=swap\" rel=\"stylesheet\" />\n    <style>\n      :root {\n        --blue: #3abadf;\n        --ink: #111827;\n        --muted: #667085;\n        --line: #d8eef5;\n        --bg: #f4f9fc;\n        --nav: #0d1b2a;\n        --orange: #ff6b00;\n        --green: #12b76a;\n        --red: #ef4444;\n      }\n      * { box-sizing: border-box; }\n      body {\n        margin: 0;\n        font-family: \"Space Grotesk\", system-ui, sans-serif;\n        color: var(--ink);\n        background: linear-gradient(180deg, rgba(58, 186, 223, .08), transparent 280px), var(--bg);\n      }\n      button, input, select, textarea { font: inherit; }\n      .layout { min-height: 100vh; display: grid; grid-template-columns: 280px 1fr; }\n      aside {\n        background: linear-gradient(180deg, var(--nav), #081522);\n        color: white;\n        padding: 26px 22px;\n        position: sticky;\n        top: 0;\n        height: 100vh;\n      }\n      .brand {\n        display: grid;\n        grid-template-columns: 56px 1fr;\n        align-items: center;\n        gap: 13px;\n        margin-bottom: 30px;\n        padding-bottom: 22px;\n        border-bottom: 1px solid rgba(216, 238, 245, .14);\n      }\n      .mark {\n        width: 56px;\n        height: 56px;\n        border-radius: 12px;\n        background: #fff;\n        display: grid;\n        place-items: center;\n        overflow: hidden;\n      }\n      .mark img { width: 42px; height: 42px; object-fit: contain; }\n      .brand strong { display: block; font-size: 16px; line-height: 1.15; }\n      .brand span { display: block; color: #a7dff0; font-size: 12px; margin-top: 4px; }\n      nav a {\n        display: flex;\n        align-items: center;\n        color: #cceefa;\n        text-decoration: none;\n        padding: 11px 12px;\n        border-radius: 8px;\n        margin-bottom: 6px;\n        font-size: 14px;\n      }\n      nav a.active, nav a:hover { background: rgba(58, 186, 223, .18); color: white; }\n      main { padding: 30px 28px 44px; max-width: 1320px; width: 100%; }\n      header {\n        display: flex;\n        justify-content: space-between;\n        gap: 20px;\n        align-items: flex-start;\n        margin-bottom: 22px;\n      }\n      .title-row { display: flex; align-items: center; gap: 14px; }\n      .header-logo {\n        width: 58px;\n        height: 58px;\n        border-radius: 12px;\n        background: white;\n        border: 1px solid var(--line);\n        padding: 8px;\n        object-fit: contain;\n      }\n      h1 { margin: 0; font-size: 34px; line-height: 1.05; letter-spacing: 0; }\n      h2 { margin: 0 0 12px; font-size: 20px; }\n      .subtitle { margin: 8px 0 0; color: var(--muted); }\n      .btn {\n        border: 0;\n        border-radius: 8px;\n        padding: 11px 14px;\n        background: var(--blue);\n        color: white;\n        font-weight: 800;\n        cursor: pointer;\n        text-decoration: none;\n        display: inline-flex;\n        align-items: center;\n      }\n      .btn.secondary { background: white; color: var(--ink); border: 1px solid var(--line); }\n      .btn.orange { background: var(--orange); }\n      .btn:disabled { opacity: .6; cursor: wait; }\n      .btn.small {\n        margin-top: 12px;\n        padding: 8px 10px;\n        font-size: 12px;\n      }\n      .grid { display: grid; gap: 16px; grid-template-columns: .95fr 1.05fr; align-items: start; }\n      .card {\n        background: #fff;\n        border: 1px solid var(--line);\n        border-radius: 8px;\n        padding: 18px;\n        box-shadow: 0 10px 26px rgba(26, 95, 117, .07);\n      }\n      .notice {\n        border-left: 4px solid var(--orange);\n        background: #fff7ed;\n        padding: 12px 14px;\n        border-radius: 8px;\n        color: #9a3412;\n        font-size: 14px;\n        margin-bottom: 14px;\n      }\n      .customer-list { display: grid; gap: 12px; }\n      .customer-card {\n        border: 1px solid #eef6f9;\n        border-radius: 8px;\n        padding: 14px;\n        background: #f8fcfe;\n      }\n      .customer-card h3 { margin: 0 0 7px; font-size: 17px; }\n      .customer-meta {\n        display: grid;\n        grid-template-columns: repeat(2, minmax(0, 1fr));\n        gap: 7px 12px;\n        margin-top: 10px;\n      }\n      .pill {\n        display: inline-flex;\n        align-items: center;\n        border-radius: 999px;\n        padding: 5px 9px;\n        background: #eef9fc;\n        color: #17677f;\n        font-size: 12px;\n        font-weight: 800;\n      }\n      .pill.green { background: #ecfdf3; color: #067647; }\n      .pill.gray { background: #f2f4f7; color: #475467; }\n      .pill.orange { background: #fff7ed; color: #c2410c; }\n      .pill.red { background: #fef3f2; color: #b42318; }\n      .small { font-size: 12px; color: var(--muted); }\n      .checklist {\n        display: grid;\n        grid-template-columns: repeat(2, minmax(0, 1fr));\n        gap: 7px 10px;\n        margin-top: 12px;\n      }\n      .check-item {\n        display: flex;\n        align-items: center;\n        gap: 7px;\n        color: var(--muted);\n        font-size: 12px;\n        font-weight: 700;\n      }\n      .check-dot {\n        width: 9px;\n        height: 9px;\n        border-radius: 999px;\n        background: var(--red);\n        flex: 0 0 auto;\n      }\n      .check-dot.ok { background: var(--green); }\n      .check-grid {\n        display: grid;\n        grid-template-columns: repeat(2, minmax(0, 1fr));\n        gap: 9px 12px;\n      }\n      .check-label {\n        display: flex;\n        align-items: center;\n        gap: 8px;\n        margin: 0;\n        color: #344054;\n        font-size: 13px;\n        font-weight: 800;\n      }\n      .check-label input { width: auto; }\n      form {\n        display: grid;\n        grid-template-columns: repeat(2, minmax(0, 1fr));\n        gap: 12px;\n      }\n      .field.full { grid-column: 1 / -1; }\n      label {\n        display: block;\n        margin-bottom: 6px;\n        color: #344054;\n        font-size: 12px;\n        font-weight: 800;\n      }\n      input, select, textarea {\n        width: 100%;\n        border: 1px solid var(--line);\n        border-radius: 8px;\n        padding: 10px 11px;\n        background: #fff;\n        color: var(--ink);\n        outline: none;\n      }\n      textarea { min-height: 92px; resize: vertical; }\n      input:focus, select:focus, textarea:focus {\n        border-color: var(--blue);\n        box-shadow: 0 0 0 4px rgba(58, 186, 223, .14);\n      }\n      .form-actions {\n        grid-column: 1 / -1;\n        display: flex;\n        align-items: center;\n        gap: 12px;\n      }\n      @media (max-width: 980px) {\n        .layout, .grid, form { grid-template-columns: 1fr; }\n        aside { position: relative; height: auto; }\n        header { flex-direction: column; }\n        .field.full { grid-column: auto; }\n      }\n    </style>\n  </head>\n  <body>\n    <div class=\"layout\">\n      <aside>\n        <div class=\"brand\">\n          <div class=\"mark\"><img src=\"/hasi-logo.png\" alt=\"Hasi Social Media\"></div>\n          <div>\n            <strong>Hasi Social Media</strong>\n            <span>Interne Verwaltung</span>\n          </div>\n        </div>\n        <nav>\n          <a class=\"active\" href=\"/admin\">Admin</a>\n          <a href=\"/logout\">Abmelden</a>\n        </nav>\n      </aside>\n      <main>\n        <header>\n          <div class=\"title-row\">\n            <img class=\"header-logo\" src=\"/hasi-logo.png\" alt=\"Hasi Social Media Logo\">\n            <div>\n              <h1>Hasi Social Media Admin</h1>\n              <p class=\"subtitle\">Kunden anlegen, Onboarding pruefen und Social-Media-Planung vorbereiten.</p>\n            </div>\n          </div>\n        </header>\n\n        <section class=\"grid\">\n          <div class=\"card\">\n            <h2>Kunden</h2>\n            <div class=\"notice\">Interne Verwaltung fuer alle Kunden. Hasi Elektronic ist hier nur ein Kunde in der Liste.</div>\n            <div class=\"customer-list\" id=\"customerList\">...</div>\n          </div>\n\n          <div class=\"card\">\n            <h2 id=\"formTitle\">Kunde anlegen</h2>\n            <form id=\"customerForm\">\n              <input id=\"customerId\" name=\"id\" type=\"hidden\">\n              <div class=\"field\">\n                <label for=\"company\">Firma *</label>\n                <input id=\"company\" name=\"company\" required placeholder=\"z.B. Muster GmbH\">\n              </div>\n              <div class=\"field\">\n                <label for=\"owner\">Ansprechpartner</label>\n                <input id=\"owner\" name=\"owner\" placeholder=\"Name\">\n              </div>\n              <div class=\"field\">\n                <label for=\"email\">E-Mail</label>\n                <input id=\"email\" name=\"email\" type=\"email\" placeholder=\"kontakt@firma.de\">\n              </div>\n              <div class=\"field\">\n                <label for=\"phone\">Telefon</label>\n                <input id=\"phone\" name=\"phone\" placeholder=\"0711 / ...\">\n              </div>\n              <div class=\"field\">\n                <label for=\"city\">Ort</label>\n                <input id=\"city\" name=\"city\" placeholder=\"Vaihingen/Enz\">\n              </div>\n              <div class=\"field\">\n                <label for=\"instagram\">Instagram</label>\n                <input id=\"instagram\" name=\"instagram\" placeholder=\"@kunde\">\n              </div>\n              <div class=\"field\">\n                <label for=\"industry\">Branche</label>\n                <input id=\"industry\" name=\"industry\" placeholder=\"Restaurant, Handwerk, Praxis ...\">\n              </div>\n              <div class=\"field\">\n                <label for=\"language\">Sprache</label>\n                <select id=\"language\" name=\"language\">\n                  <option value=\"de\">Deutsch</option>\n                  <option value=\"tr\">Tuerkisch</option>\n                  <option value=\"en\">Englisch</option>\n                </select>\n              </div>\n              <div class=\"field\">\n                <label for=\"primary\">Hauptfarbe</label>\n                <input id=\"primary\" name=\"primary\" value=\"#3ABADF\">\n              </div>\n              <div class=\"field\">\n                <label for=\"accent\">Akzentfarbe</label>\n                <input id=\"accent\" name=\"accent\" value=\"#FF6B00\">\n              </div>\n              <div class=\"field full\">\n                <label for=\"topics\">Themen</label>\n                <input id=\"topics\" name=\"topics\" placeholder=\"Angebote, Team, Tipps, Referenzen\">\n              </div>\n              <div class=\"field\">\n                <label for=\"carouselTime\">Karussell Zeit</label>\n                <input id=\"carouselTime\" name=\"carouselTime\" value=\"08:00\">\n              </div>\n              <div class=\"field\">\n                <label for=\"reelTime\">Reel Zeit</label>\n                <input id=\"reelTime\" name=\"reelTime\" value=\"08:30\">\n              </div>\n              <div class=\"field\">\n                <label for=\"storyTime\">Story Zeit</label>\n                <input id=\"storyTime\" name=\"storyTime\" value=\"09:00\">\n              </div>\n              <div class=\"field full\">\n                <label for=\"positioning\">Positionierung</label>\n                <textarea id=\"positioning\" name=\"positioning\" placeholder=\"Wofuer steht der Kunde? Was soll Social Media verkaufen oder erklaeren?\"></textarea>\n              </div>\n              <div class=\"field full\">\n                <label>Onboarding Checklist</label>\n                <div class=\"check-grid\">\n                  <label class=\"check-label\"><input id=\"profileComplete\" name=\"profileComplete\" type=\"checkbox\"> Profil vollständig</label>\n                  <label class=\"check-label\"><input id=\"brandComplete\" name=\"brandComplete\" type=\"checkbox\"> Logo / Marke vollständig</label>\n                  <label class=\"check-label\"><input id=\"productPhotos\" name=\"productPhotos\" type=\"checkbox\"> Produktfotos vorhanden</label>\n                  <label class=\"check-label\"><input id=\"productList\" name=\"productList\" type=\"checkbox\"> Produktliste / Preise vorhanden</label>\n                  <label class=\"check-label\"><input id=\"instagramBusiness\" name=\"instagramBusiness\" type=\"checkbox\"> Instagram Business verbunden</label>\n                  <label class=\"check-label\"><input id=\"facebookPage\" name=\"facebookPage\" type=\"checkbox\"> Facebook Page verbunden</label>\n                  <label class=\"check-label\"><input id=\"metaAccess\" name=\"metaAccess\" type=\"checkbox\"> Meta Business Zugriff erteilt</label>\n                  <label class=\"check-label\"><input id=\"contentPlan\" name=\"contentPlan\" type=\"checkbox\"> Content Plan eingerichtet</label>\n                </div>\n              </div>\n              <div class=\"field full\">\n                <label for=\"publishPermission\">Yayın onayı</label>\n                <select id=\"publishPermission\" name=\"publishPermission\">\n                  <option value=\"missing\">Noch offen</option>\n                  <option value=\"approval\">Erst Freigabe, dann Publish</option>\n                  <option value=\"direct\">Direkt veroeffentlichen erlaubt</option>\n                </select>\n              </div>\n              <div class=\"field full\">\n                <label for=\"onboardingNotes\">Onboarding Notizen</label>\n                <textarea id=\"onboardingNotes\" name=\"notes\" placeholder=\"Was fehlt noch? Wer muss was liefern?\"></textarea>\n              </div>\n              <div class=\"form-actions\">\n                <button class=\"btn orange\" id=\"submitCustomer\" type=\"submit\">Kunde anlegen</button>\n                <button class=\"btn secondary\" id=\"resetForm\" type=\"button\">Neu</button>\n                <span class=\"small\" id=\"customerFormStatus\"></span>\n              </div>\n            </form>\n          </div>\n        </section>\n      </main>\n    </div>\n    <script>\n      const $ = (id) => document.getElementById(id);\n      const state = { customers: [], editingId: \"\" };\n\n      async function api(path, options) {\n        const response = await fetch(path, options);\n        const data = await response.json();\n        if (!response.ok) throw new Error(data.error || \"API Fehler\");\n        return data;\n      }\n\n      function escapeHtml(value) {\n        return String(value ?? \"\")\n          .replaceAll(\"&\", \"&amp;\")\n          .replaceAll(\"<\", \"&lt;\")\n          .replaceAll(\">\", \"&gt;\")\n          .replaceAll('\"', \"&quot;\")\n          .replaceAll(\"'\", \"&#039;\");\n      }\n\n      function onboardingStatus(customer) {\n        const ob = customer.onboarding || {};\n        const mediaOk = Boolean(ob.productPhotos && ob.productList && ob.instagramBusiness && ob.facebookPage && ob.metaAccess && ob.publishPermission !== \"missing\");\n        if (!ob.profileComplete) return { label: \"Profil eksik\", cls: \"red\" };\n        if (!ob.brandComplete) return { label: \"Marka bilgileri eksik\", cls: \"orange\" };\n        if (!mediaOk) return { label: \"Medya erişimi eksik\", cls: \"orange\" };\n        if (!ob.contentPlan) return { label: \"İçerik planı eksik\", cls: \"orange\" };\n        return { label: \"Yayına hazır\", cls: \"green\" };\n      }\n\n      function checklist(customer) {\n        const ob = customer.onboarding || {};\n        return [\n          [\"Profil\", ob.profileComplete],\n          [\"Logo / Marka\", ob.brandComplete],\n          [\"Ürün foto\", ob.productPhotos],\n          [\"Ürün liste\", ob.productList],\n          [\"Instagram Business\", ob.instagramBusiness],\n          [\"Facebook Page\", ob.facebookPage],\n          [\"Meta Zugriff\", ob.metaAccess],\n          [\"Content Plan\", ob.contentPlan],\n        ].map(([label, ok]) => `\n          <div class=\"check-item\"><span class=\"check-dot ${ok ? \"ok\" : \"\"}\"></span>${label}</div>\n        `).join(\"\");\n      }\n\n      function renderCustomers(customers = []) {\n        state.customers = customers;\n        $(\"customerList\").innerHTML = customers.map((customer) => `\n          <article class=\"customer-card\">\n            <h3>${escapeHtml(customer.company || customer.name)}</h3>\n            <div>\n              <span class=\"pill green\">${escapeHtml(customer.status || \"active\")}</span>\n              <span class=\"pill ${onboardingStatus(customer).cls}\">${onboardingStatus(customer).label}</span>\n              ${customer.instagram ? `<span class=\"pill\">${escapeHtml(customer.instagram)}</span>` : \"\"}\n              ${customer.language ? `<span class=\"pill gray\">${escapeHtml(customer.language)}</span>` : \"\"}\n            </div>\n            <div class=\"customer-meta small\">\n              <div><strong>ID</strong><br>${escapeHtml(customer.id)}</div>\n              <div><strong>Branche</strong><br>${escapeHtml(customer.industry || \"-\")}</div>\n              <div><strong>Kontakt</strong><br>${escapeHtml(customer.owner || \"-\")}</div>\n              <div><strong>Ort</strong><br>${escapeHtml(customer.city || \"-\")}</div>\n            </div>\n            <div class=\"checklist\">${checklist(customer)}</div>\n            ${customer.onboarding?.notes ? `<p class=\"small\" style=\"margin:12px 0 0\"><strong>Notiz:</strong> ${escapeHtml(customer.onboarding.notes)}</p>` : \"\"}\n            ${customer.positioning ? `<p class=\"small\" style=\"margin:12px 0 0\">${escapeHtml(customer.positioning)}</p>` : \"\"}\n            <button class=\"btn secondary small js-edit-customer\" type=\"button\" data-id=\"${escapeHtml(customer.id)}\">Bearbeiten</button>\n            <a class=\"btn secondary small\" href=\"/kunde/${encodeURIComponent(customer.id)}\">Kundenseite öffnen</a>\n          </article>\n        `).join(\"\") || `<div class=\"small\">Noch keine Kunden angelegt.</div>`;\n      }\n\n      function resetCustomerForm() {\n        state.editingId = \"\";\n        $(\"customerForm\").reset();\n        $(\"customerId\").value = \"\";\n        $(\"primary\").value = \"#3ABADF\";\n        $(\"accent\").value = \"#FF6B00\";\n        $(\"language\").value = \"de\";\n        $(\"carouselTime\").value = \"08:00\";\n        $(\"reelTime\").value = \"08:30\";\n        $(\"storyTime\").value = \"09:00\";\n        $(\"publishPermission\").value = \"missing\";\n        $(\"formTitle\").textContent = \"Kunde anlegen\";\n        $(\"submitCustomer\").textContent = \"Kunde anlegen\";\n        $(\"customerFormStatus\").textContent = \"\";\n      }\n\n      function editCustomer(id) {\n        const customer = state.customers.find((item) => item.id === id);\n        if (!customer) return;\n        const ob = customer.onboarding || {};\n        state.editingId = customer.id;\n        $(\"customerId\").value = customer.id;\n        $(\"company\").value = customer.company || customer.name || \"\";\n        $(\"owner\").value = customer.owner || \"\";\n        $(\"email\").value = customer.email || \"\";\n        $(\"phone\").value = customer.phone || \"\";\n        $(\"city\").value = customer.city || \"\";\n        $(\"instagram\").value = customer.instagram || \"\";\n        $(\"industry\").value = customer.industry || \"\";\n        $(\"language\").value = customer.language || \"de\";\n        $(\"primary\").value = customer.brand?.primary || \"#3ABADF\";\n        $(\"accent\").value = customer.brand?.accent || \"#FF6B00\";\n        $(\"topics\").value = (customer.topics || []).join(\", \");\n        $(\"carouselTime\").value = customer.cadence?.carousel || \"08:00\";\n        $(\"reelTime\").value = customer.cadence?.reel || \"08:30\";\n        $(\"storyTime\").value = customer.cadence?.story || \"09:00\";\n        $(\"positioning\").value = customer.positioning || \"\";\n        $(\"profileComplete\").checked = Boolean(ob.profileComplete);\n        $(\"brandComplete\").checked = Boolean(ob.brandComplete);\n        $(\"productPhotos\").checked = Boolean(ob.productPhotos);\n        $(\"productList\").checked = Boolean(ob.productList);\n        $(\"instagramBusiness\").checked = Boolean(ob.instagramBusiness);\n        $(\"facebookPage\").checked = Boolean(ob.facebookPage);\n        $(\"metaAccess\").checked = Boolean(ob.metaAccess);\n        $(\"contentPlan\").checked = Boolean(ob.contentPlan);\n        $(\"publishPermission\").value = ob.publishPermission || \"missing\";\n        $(\"onboardingNotes\").value = ob.notes || \"\";\n        $(\"formTitle\").textContent = `${customer.company || customer.name} bearbeiten`;\n        $(\"submitCustomer\").textContent = \"Kunde speichern\";\n        $(\"customerFormStatus\").textContent = \"Bearbeitungsmodus\";\n        window.scrollTo({ top: 0, behavior: \"smooth\" });\n      }\n\n      async function refreshCustomers() {\n        const data = await api(\"/api/customers\");\n        renderCustomers(data.customers || []);\n      }\n\n      async function createCustomer(event) {\n        event.preventDefault();\n        const form = event.currentTarget;\n        const status = $(\"customerFormStatus\");\n        const button = form.querySelector(\"button[type='submit']\");\n        status.textContent = \"Speichern...\";\n        button.disabled = true;\n        const payload = Object.fromEntries(new FormData(form).entries());\n        payload.secondary = payload.primary || \"#41AADE\";\n        for (const key of [\"profileComplete\", \"brandComplete\", \"productPhotos\", \"productList\", \"instagramBusiness\", \"facebookPage\", \"metaAccess\", \"contentPlan\"]) {\n          payload[key] = form.elements[key].checked;\n        }\n        try {\n          const path = state.editingId ? `/api/customers/${encodeURIComponent(state.editingId)}` : \"/api/customers\";\n          await api(path, {\n            method: state.editingId ? \"PUT\" : \"POST\",\n            headers: { \"Content-Type\": \"application/json\" },\n            body: JSON.stringify(payload),\n          });\n          status.textContent = state.editingId ? \"Kunde gespeichert.\" : \"Kunde angelegt.\";\n          resetCustomerForm();\n          await refreshCustomers();\n        } catch (error) {\n          status.textContent = error.message;\n        } finally {\n          button.disabled = false;\n        }\n      }\n\n      $(\"customerForm\").addEventListener(\"submit\", createCustomer);\n      $(\"resetForm\").addEventListener(\"click\", resetCustomerForm);\n      document.addEventListener(\"click\", (event) => {\n        const edit = event.target.closest(\".js-edit-customer\");\n        if (edit) editCustomer(edit.dataset.id);\n      });\n      refreshCustomers().catch((error) => {\n        $(\"customerList\").textContent = error.message;\n      });\n    </script>\n  </body>\n</html>\n";

function base64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function textBytes(value) {
  return new TextEncoder().encode(value);
}

async function sha256Hex(value) {
  const digest = await crypto.subtle.digest("SHA-256", textBytes(value));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function hmac(secret, value) {
  const key = await crypto.subtle.importKey(
    "raw",
    textBytes(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, textBytes(value));
  return base64Url(new Uint8Array(signature));
}

function readCookie(request, name) {
  const cookie = request.headers.get("Cookie") || "";
  return cookie
    .split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith(`${name}=`))
    ?.slice(name.length + 1);
}

async function createSession(email, env) {
  const payload = base64Url(textBytes(JSON.stringify({
    email,
    exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS,
  })));
  const sig = await hmac(env.SESSION_SECRET, payload);
  return `${payload}.${sig}`;
}

async function verifySession(request, env) {
  const token = readCookie(request, SESSION_COOKIE);
  if (!token || !token.includes(".")) return false;
  const [payload, sig] = token.split(".");
  const expected = await hmac(env.SESSION_SECRET, payload);
  if (sig !== expected) return false;
  try {
    const json = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(payload.replaceAll("-", "+").replaceAll("_", "/")), (char) => char.charCodeAt(0))));
    return json.exp > Math.floor(Date.now() / 1000);
  } catch {
    return false;
  }
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}

function clearSessionCookie() {
  return `${SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`;
}

async function serveAsset(env, path, request) {
  const url = new URL(request.url);
  url.pathname = path;
  return env.ASSETS.fetch(new Request(url, request));
}

async function handleLogin(request, env) {
  const body = await request.json().catch(() => ({}));
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");
  const expectedEmail = String(env.COCKPIT_EMAIL || "").trim().toLowerCase();
  const salt = env.COCKPIT_PASSWORD_SALT || "";
  const hash = await sha256Hex(`${salt}:${password}`);
  const hashMatches = env.COCKPIT_PASSWORD_HASH && hash === env.COCKPIT_PASSWORD_HASH;
  const secretMatches = env.COCKPIT_PASSWORD && password === env.COCKPIT_PASSWORD;
  if (!expectedEmail || email !== expectedEmail || (!hashMatches && !secretMatches)) {
    return json({ ok: false }, 401);
  }
  const session = await createSession(email, env);
  return new Response(JSON.stringify({ ok: true }), {
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Set-Cookie": `${SESSION_COOKIE}=${session}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${SESSION_TTL_SECONDS}`,
    },
  });
}

function contentTypeOk(type, expected) {
  return String(type || "").toLowerCase().includes(expected);
}

function manifestSlug(file) {
  return String(file || "").replace(/\.manifest\.json$/, "").replace(/\.(reel|story)$/, "");
}

function safePublishFile(value) {
  return String(value || "").replace(/[^a-zA-Z0-9._-]/g, "");
}

async function activityLog(env, request) {
  const fallbackResponse = await serveAsset(env, "/data/status.json", request);
  const snapshot = fallbackResponse.ok ? await fallbackResponse.json().catch(() => ({})) : {};
  const staticLog = Array.isArray(snapshot.log) ? snapshot.log : [];
  const storedLog = env.CUSTOMERS ? await env.CUSTOMERS.get("activity-log", "json") : [];
  const combined = [...(Array.isArray(storedLog) ? storedLog : []), ...staticLog];
  const seen = new Set();
  return combined.filter((entry) => {
    const key = `${entry.action || ""}:${entry.manifest || ""}:${entry.instagramId || ""}:${entry.time || ""}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).sort((a, b) => new Date(b.time || 0).getTime() - new Date(a.time || 0).getTime());
}

async function appendActivityLog(env, request, entry) {
  if (!env.CUSTOMERS) throw new Error("CUSTOMERS KV binding fehlt");
  const log = await activityLog(env, request);
  const next = [entry, ...log].slice(0, 100);
  await env.CUSTOMERS.put("activity-log", JSON.stringify(next, null, 2));
}

function applyPublishedLog(snapshot, log) {
  const items = Array.isArray(snapshot.manifests) ? snapshot.manifests : [];
  snapshot.manifests = items.map((item) => {
    const published = log.find((entry) => {
      if (entry.status !== "published" && !entry.instagramId) return false;
      return entry.manifest === item.file || entry.slug === item.slug || entry.slug === manifestSlug(item.file);
    });
    return published ? {
      ...item,
      published: true,
      publishedAt: published.time || item.publishedAt || "",
      instagramId: published.instagramId || item.instagramId || "",
    } : item;
  });
  snapshot.log = log.slice(0, 50);
  return snapshot;
}

async function status(env, request) {
  const response = await serveAsset(env, "/data/status.json", request);
  if (!response.ok) return json({ error: "Status snapshot not found" }, 404);
  const snapshot = await response.json();
  snapshot.customers = await customers(env, request);
  return json(applyPublishedLog(snapshot, await activityLog(env, request)));
}

function slugify(value) {
  return String(value || "")
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 64);
}

function parseTopics(value) {
  if (Array.isArray(value)) return value.map((item) => String(item).trim()).filter(Boolean).slice(0, 12);
  return String(value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean)
    .slice(0, 12);
}

function boolValue(value) {
  return value === true || value === "true" || value === "on" || value === "1";
}

function normalizeOnboarding(input = {}, existing = {}) {
  return {
    profileComplete: boolValue(input.profileComplete ?? existing.profileComplete),
    brandComplete: boolValue(input.brandComplete ?? existing.brandComplete),
    productPhotos: boolValue(input.productPhotos ?? existing.productPhotos),
    productList: boolValue(input.productList ?? existing.productList),
    instagramBusiness: boolValue(input.instagramBusiness ?? existing.instagramBusiness),
    facebookPage: boolValue(input.facebookPage ?? existing.facebookPage),
    metaAccess: boolValue(input.metaAccess ?? existing.metaAccess),
    contentPlan: boolValue(input.contentPlan ?? existing.contentPlan),
    publishPermission: String(input.publishPermission || existing.publishPermission || "missing").trim(),
    notes: String(input.notes ?? existing.notes ?? "").trim(),
    updatedAt: new Date().toISOString(),
  };
}

function normalizeCadence(input = {}, existing = {}) {
  return {
    carousel: String(input.carouselTime || input.carousel || existing.carousel || "08:00").trim(),
    reel: String(input.reelTime || input.reel || existing.reel || "08:30").trim(),
    story: String(input.storyTime || input.story || existing.story || "09:00").trim(),
  };
}

function normalizeCustomer(input, existing = null) {
  const company = String(input.company || input.name || "").trim();
  if (!company) throw new Error("Firma fehlt");
  const id = slugify(existing?.id || input.id || company);
  if (!id) throw new Error("Kunden-ID fehlt");
  const onboardingInput = input.onboarding || input;
  const brandInput = input.brand || {};
  const cadenceInput = input.cadence || input;
  return {
    id,
    name: company,
    company,
    owner: String(input.owner || "").trim(),
    email: String(input.email || "").trim(),
    phone: String(input.phone || "").trim(),
    city: String(input.city || "").trim(),
    address: String(input.address || "").trim(),
    instagram: String(input.instagram || "").trim(),
    industry: String(input.industry || "").trim(),
    language: String(input.language || "de").trim(),
    status: String(input.status || "active").trim(),
    brand: {
      primary: String(input.primary || brandInput.primary || "#3ABADF").trim(),
      secondary: String(input.secondary || brandInput.secondary || input.primary || brandInput.primary || "#41AADE").trim(),
      accent: String(input.accent || brandInput.accent || "#FF6B00").trim(),
      font: String(input.font || brandInput.font || "Space Grotesk").trim(),
      logo: String(input.logo || brandInput.logo || "").trim(),
    },
    topics: parseTopics(input.topics),
    cadence: normalizeCadence(cadenceInput, existing?.cadence),
    positioning: String(input.positioning || "").trim(),
    onboarding: normalizeOnboarding(onboardingInput, existing?.onboarding),
    createdAt: existing?.createdAt || new Date().toISOString(),
  };
}

async function fallbackCustomers(env, request) {
  const response = await serveAsset(env, "/data/customers.json", request);
  if (!response.ok) return [];
  return response.json();
}

async function customers(env, request) {
  if (env.CUSTOMERS) {
    const stored = await env.CUSTOMERS.get("customers", "json");
    if (Array.isArray(stored)) return stored.map((row) => normalizeCustomer(row, row));
  }
  const rows = await fallbackCustomers(env, request);
  return rows.map((row) => normalizeCustomer(row, row));
}

async function saveCustomers(env, rows) {
  if (!env.CUSTOMERS) throw new Error("CUSTOMERS KV binding fehlt");
  await env.CUSTOMERS.put("customers", JSON.stringify(rows, null, 2));
}

async function addCustomer(request, env) {
  const customer = normalizeCustomer(await request.json());
  const rows = await customers(env, request);
  if (rows.some((row) => row.id === customer.id)) {
    return json({ error: "Kunde existiert bereits" }, 409);
  }
  const nextRows = [customer, ...rows];
  await saveCustomers(env, nextRows);
  return json({ customer }, 201);
}

async function updateCustomer(request, env, id) {
  const input = await request.json();
  const rows = await customers(env, request);
  const index = rows.findIndex((row) => row.id === id);
  if (index === -1) return json({ error: "Kunde nicht gefunden" }, 404);
  const customer = normalizeCustomer({ ...rows[index], ...input }, rows[index]);
  const nextRows = rows.map((row, rowIndex) => rowIndex === index ? customer : row);
  await saveCustomers(env, nextRows);
  return json({ customer });
}

function graphConfig(env) {
  const igUserId = env.IG_USER_ID;
  const accessToken = env.IG_ACCESS_TOKEN;
  if (!igUserId || !accessToken) throw new Error("Instagram Cloud Secrets fehlen: IG_USER_ID / IG_ACCESS_TOKEN");
  return {
    igUserId,
    accessToken,
    version: env.GRAPH_API_VERSION || "v25.0",
    graphHost: env.IG_GRAPH_HOST || "graph.instagram.com",
  };
}

async function graphPost(env, path, params) {
  const config = graphConfig(env);
  const body = new URLSearchParams({ ...params, access_token: config.accessToken });
  const response = await fetch(`https://${config.graphHost}/${config.version}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  const data = await response.json();
  if (!response.ok || data.error) throw new Error(JSON.stringify(data.error || data));
  return data;
}

async function graphGet(env, path, params = {}) {
  const config = graphConfig(env);
  const url = new URL(`https://${config.graphHost}/${config.version}${path}`);
  url.search = new URLSearchParams({ ...params, access_token: config.accessToken }).toString();
  const response = await fetch(url);
  const data = await response.json();
  if (!response.ok || data.error) throw new Error(JSON.stringify(data.error || data));
  return data;
}

async function waitForContainer(env, containerId, attempts = 24) {
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    const status = await graphGet(env, `/${containerId}`, { fields: "status_code,status" });
    if (status.status_code === "FINISHED") return;
    if (status.status_code === "ERROR") throw new Error(`Container ${containerId} failed: ${status.status || "unknown error"}`);
    await new Promise((resolve) => setTimeout(resolve, 3000));
  }
  throw new Error(`Container ${containerId} wurde nicht rechtzeitig fertig.`);
}

async function findManifest(env, request, file) {
  const response = await serveAsset(env, "/data/status.json", request);
  if (!response.ok) throw new Error("Status snapshot not found");
  const snapshot = await response.json();
  return (snapshot.manifests || []).find((item) => item.file === file);
}

async function verifyPublishItem(item) {
  if (!item || !Array.isArray(item.urls) || item.urls.length === 0) throw new Error("Manifest nicht gefunden oder ohne URLs.");
  const checks = await Promise.all(item.urls.map(async (url) => {
    const response = await fetch(url, { method: "HEAD" });
    return { ok: response.ok, status: response.status, type: response.headers.get("content-type") || "" };
  }));
  if (item.type === "carousel" && !checks.every((check) => check.ok && contentTypeOk(check.type, "image/png"))) {
    throw new Error("Karussell ist nicht publish-ready: Bild-URLs liefern nicht alle image/png.");
  }
  if (item.type === "reel" && !checks.every((check) => check.ok && contentTypeOk(check.type, "video/mp4"))) {
    throw new Error("Reel ist nicht publish-ready: Video-URL liefert kein video/mp4.");
  }
}

async function publishCarousel(env, item) {
  if (item.urls.length < 2 || item.urls.length > 10) throw new Error("Instagram Karussell braucht 2 bis 10 Bilder.");
  const children = [];
  for (const imageUrl of item.urls) {
    const child = await graphPost(env, `/${graphConfig(env).igUserId}/media`, {
      image_url: imageUrl,
      is_carousel_item: "true",
    });
    await waitForContainer(env, child.id, 20);
    children.push(child.id);
  }
  const parent = await graphPost(env, `/${graphConfig(env).igUserId}/media`, {
    media_type: "CAROUSEL",
    children: children.join(","),
    caption: item.caption || "",
  });
  await waitForContainer(env, parent.id, 20);
  return graphPost(env, `/${graphConfig(env).igUserId}/media_publish`, { creation_id: parent.id });
}

async function publishReel(env, item) {
  const container = await graphPost(env, `/${graphConfig(env).igUserId}/media`, {
    media_type: "REELS",
    video_url: item.urls[0],
    caption: item.caption || "",
    share_to_feed: "true",
  });
  await waitForContainer(env, container.id, 60);
  return graphPost(env, `/${graphConfig(env).igUserId}/media_publish`, { creation_id: container.id });
}

async function publishFromCloud(request, env, type, file) {
  if (!["carousel", "reel"].includes(type)) {
    return json({ ok: false, error: "Cloud Publish v1 erlaubt nur Karussell und Reel. Story bleibt publish-ready." }, 403);
  }
  const safeFile = safePublishFile(file);
  const item = await findManifest(env, request, safeFile);
  if (!item || item.type !== type) return json({ ok: false, error: "Manifest nicht gefunden oder falscher Typ." }, 404);

  const log = await activityLog(env, request);
  const already = log.find((entry) => (entry.status === "published" || entry.instagramId) && (entry.manifest === safeFile || entry.slug === item.slug));
  if (already) {
    return json({ ok: true, skipped: true, instagramId: already.instagramId || "", message: "Schon veröffentlicht." });
  }

  try {
    await verifyPublishItem(item);
    const published = type === "carousel" ? await publishCarousel(env, item) : await publishReel(env, item);
    const entry = {
      time: new Date().toISOString(),
      action: `publish-${type}`,
      status: "published",
      type,
      topic: item.slug || manifestSlug(safeFile),
      slug: item.slug || manifestSlug(safeFile),
      manifest: safeFile,
      instagramId: published.id || "",
      note: "Cloud Publish v1 über Hasi Social Media.",
    };
    await appendActivityLog(env, request, entry);
    return json({ ok: true, instagramId: published.id || "", entry });
  } catch (error) {
    await appendActivityLog(env, request, {
      time: new Date().toISOString(),
      action: `publish-${type}`,
      status: "failed",
      type,
      topic: item.slug || manifestSlug(safeFile),
      slug: item.slug || manifestSlug(safeFile),
      manifest: safeFile,
      instagramId: "",
      note: String(error.message || error).slice(0, 500),
    }).catch(() => {});
    return json({ ok: false, error: String(error.message || error) }, 500);
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/login" || url.pathname === "/login.html") {
      return new Response(LOGIN_HTML, {
        headers: {
          "Content-Type": "text/html; charset=utf-8",
          "Set-Cookie": clearSessionCookie(),
        },
      });
    }
    if (url.pathname === "/api/login" && request.method === "POST") {
      return handleLogin(request, env);
    }
    if (url.pathname === "/hasi-logo.png") {
      return serveAsset(env, "/hasi-logo.png", request);
    }
    if (url.pathname === "/logout") {
      return new Response(null, {
        status: 302,
        headers: {
          Location: "/login",
          "Set-Cookie": clearSessionCookie(),
        },
      });
    }

    if (!(await verifySession(request, env))) {
      if (url.pathname.startsWith("/api/")) return json({ error: "Unauthorized" }, 401);
      const next = `${url.pathname}${url.search}`;
      return Response.redirect(`${url.origin}/login?next=${encodeURIComponent(next)}`, 302);
    }

    if (url.pathname === "/admin" || url.pathname === "/admin.html") {
      return new Response(ADMIN_HTML, {
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }
    if (url.pathname.startsWith("/kunde/")) return serveAsset(env, "/index.html", request);
    if (url.pathname === "/api/status") return status(env, request);
    if (url.pathname === "/api/customers" && request.method === "GET") {
      return json({ customers: await customers(env, request) });
    }
    if (url.pathname === "/api/customers" && request.method === "POST") {
      return addCustomer(request, env);
    }
    if (url.pathname.startsWith("/api/customers/") && request.method === "PUT") {
      const id = decodeURIComponent(url.pathname.replace("/api/customers/", ""));
      return updateCustomer(request, env, id);
    }
    if (url.pathname.startsWith("/api/publish/") && request.method === "POST") {
      const [, , , type, ...fileParts] = url.pathname.split("/");
      return publishFromCloud(request, env, type, decodeURIComponent(fileParts.join("/") || ""));
    }
    return env.ASSETS.fetch(request);
  },
};
