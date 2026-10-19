# Sikkerhedsreview af Sentinel

Dato: 19. oktober 2026. Metode: statisk kodegennemgang af hele projektet samt
`npm audit`. Ingen dynamisk test eller exploit. Fundene er ikke bevist i runtime.

## Samlet vurdering

Ingen kritiske fund. Grundstrukturen er sund: parameteriserede D1-queries, Astro
escoper alt, session fixation er håndteret, og login har konstant-tids
sammenligning. De væsentligste risici ligger i **agent/ingest-flowet**,
**notifikationsvejen** (`send_email` uden begrænsning) og **login-rate-limiting**.

## Fund

### Høj

**H-1. `/api/ingest` er svagt hærdet**
`src/pages/api/ingest.ts`, `src/server/repo.ts`
Ingen rate limit, ingen body-grænse, svag feltvalidering, og opslag sker kun på
MAC globalt (ikke pr. agent). Et lækket agent-token kan overskrive enheder,
forgifte historik og udløse op til 1000 notifikationer pr. request.
Ret: validér MAC/IP/længder, scope opslag på agent, body-loft, rate limit,
aggregér notifikationer.

**H-2. `send_email` er ubegrænset**
`wrangler.jsonc`, `src/server/email.ts`, `src/pages/api/settings/*`
Bindingen har ingen `allowed_destination_addresses`, og der er ingen rate limit
på notifikationer. En kompromitteret session kan sende vilkårlige mails fra
domenet.
Ret: begræns destinationer i bindingen, validér afsender, rate limit, max antal
modtagere.

### Mellem

- **M-1. Login-rate-limiting** er pr. IP+brugernavn (omgås distribueret), ingen
  body-grænse, `rate_limits` ryddes aldrig. Bootstrap har ingen limit.
- **M-2. PBKDF2 100k** er under OWASP-anbefalingen, og iterations-tallet fra DB
  har intet loft. Kommentaren i `auth.ts` siger 600k.
- **M-3. Sessioner gemmes i klartekst** i D1, 7 dages fast levetid, ingen idle
  timeout, ingen "log ud alle", ingen password-change.
- **M-4. CSP tillader `'unsafe-inline'`** for scripts, og `incidents.astro`
  bruger `onchange=` inline.
- **M-5. Uptime-validering er syntaktisk**; DNS-baseret SSRF er ikke afvist.
  `degraded` lukker hændelsen som var den oppe.
- **M-6. Ingen body-/feltgrænser** på form- og JSON-endpoints (undtagen noter).
- **M-7. E-mail/webhook valideres svagt** (afsender, `http://`, CR/LF, URL i logs).
- **M-8. Agenten kører som root**, og dry-run lækker token via kommandolinjen.
- **M-9. Ingen dataretention** for enheder, hændelser, sessioner eller rate limits.

### Lav

- L-1. Origin-tjek undtager `/api/auth/*`; JSON-endpoints kræver ikke content-type.
- L-2. Mangler `Cache-Control: no-store`, HSTS og headers på 403-svar.
- L-3. Cookie uden `__Host-`-prefix og uden idle-timeout.
- L-4. `degraded` lukker alarm; `raiseAlert` er ikke atomisk (duplikater).
- L-5. Ingen audit-log; fejllogs kan indeholde webhook-URL.
- L-6. Aktivtypen `key` kan friste til at gemme hemmeligheder i klartekst.
- L-7. `site_url` udledes af Host-header; webhook-URL vises i klartekst.
- L-8. Docs afviger fra koden (bl.a. "data gemmes kun på denne maskine", 600k vs 100k).

### Info

- `npm audit`: 0 sårbarheder i 358 pakker.
- Ingen hemmeligheder fundet i repo. `.dev.vars` og `.wrangler` er ignoreret.
- Noter: AES-GCM uden AAD; titel er ikke autentiseret. Lav risiko.

## Status efter rettelser (19. oktober 2026)

Følgende er rettet i koden efter denne review:

- **H-1:** ingest validerer MAC/IP/længder, er scopet pr. agent, har body-loft
  (2 MB), maks. 1000 enheder, maks. 100 hændelser pr. kørsel, og notifikationer
  er budgetteret.
- **H-2:** `send_email` er bundet til én modtager og én afsender, og
  notifikationer er begrænset til 30/time (test: 5/time).
- **M-1:** login har både konto/IP- og IP-loft samt body-grænse; bootstrap har
  eget loft; `rate_limits` ryddes i cron.
- **M-2:** kommentar rettet til 100k, og iterations-tallet valideres (max 1 mio.).
- **M-3:** session-id'er gemmes kun som SHA-256, med 12 timers idle-timeout og
  "log ud alle".
- **M-4:** inline `onchange` fjernet; CSP strammet med `object-src`, `frame-src`,
  `worker-src`, `base-uri 'none'` og `upgrade-insecure-requests`. `script-src`
  har stadig `'unsafe-inline'` pga. Astros inlinede scripts.
- **M-9:** cron sletter udløbne sessioner, gamle rate limits, enheder ikke set i
  180 dage og løste hændelser ældre end et år.
- **L-2:** HSTS, Permissions-Policy, `no-store` og sikkerhedsheaders på 403-svar.
- **L-3 (delvist):** idle-timeout tilføjet; cookie-prefix `__Host-` er ikke ændret.
- **L-8:** dokumentationen rettet, så den matcher koden.

Stadig åbne (bevidst fravalgt): DNS-baseret SSRF-validering (M-5), agentens
root-kørsel (M-8), Argon2/pepper (M-2) og fuld CSP uden `unsafe-inline` (M-4).

## Anbefalet rækkefølge (oprindelig)

1. H-2: begræns `send_email` og indfør notifikations-rate-limit.
2. H-1: hærd ingest (validering, agent-scope, body-loft, aggregering).
3. M-1: IP-bredt login-loft + body-grænser + oprydning af `rate_limits`.
4. M-3: hash session-id'er, idle timeout, "log ud alle".
5. M-4: fjern inline `onchange`, stram CSP.
6. M-5, M-6, M-7: validering og grænser.
7. M-9: retention-job i cron.
8. L-* og doc-rettelser.
