# Deploy af Sentinel til Cloudflare

Komplet guide fra tom konto til kørende site.

## 0. Forudsætninger

- Node.js (projektet kræver `>=22.22.0`) og npm
- En Cloudflare-konto (gratis)
- `wrangler` ligger allerede som dev-dependency, så brug `npx wrangler ...`

```sh
npm install              # installerer afhængigheder inkl. wrangler
npx wrangler --version   # bekræft at wrangler virker
```

## 1. Log ind på Cloudflare

```sh
npx wrangler login
npx wrangler whoami
```

`wrangler login` åbner en browser og beder om adgang til din konto.

## 2. Opret D1-databasen

```sh
npx wrangler d1 create sentinel
```

Kommandoen svarer med noget i retning af:

```toml
database_id = "a1b2c3d4-...."
```

Åbn `wrangler.jsonc` og erstat pladsholderen:

```jsonc
"database_id": "REPLACE_WITH_D1_DATABASE_ID"
```

med det id, du lige fik. `binding` skal forblive `DB`, og `database_name`
skal være `sentinel`.

## 3. Kør skemaet på den rigtige database

```sh
npm run cf-migrate:remote
```

Dette opretter tabellerne `users`, `sessions`, `assets`, `monitors`, `incidents`,
`notes`, `agents`, `devices`, `settings` og `rate_limits`. **Dette skal gøres, før du
besøger sitet**, ellers fejler siderne med "no such table".

Vil du se hvad der ligger i basen:

```sh
npx wrangler d1 execute DB --remote --command "SELECT name FROM sqlite_master WHERE type='table'"
```

## 4. Valgfrit: hemmeligheder og variabler

E-mail-lækage-tjek bruger Have I Been Pwned og kræver en API-nøgle:

```sh
npx wrangler secret put HIBP_API_KEY
```

Uden nøglen virker adgangskode-tjekket stadig; e-mail-feltet melder
"ikke konfigureret".

Vil du have e-mail-notifikationer, bruges Cloudflares egen afsendelse via
`send_email`-bindingen (allerede i `wrangler.jsonc`). Det kræver:

1. At dit domæne er på Cloudflare og aktiveret til **Email Service** (afsendelse).
2. At modtageradressen er tilføjet som en godkendt destination i Cloudflare.
3. At afsenderen er en adresse på dit domæne, fx `sentinel@example.com`.

Der er ingen API-nøgle og ingen tredjepart. Sæt modtager og afsender under
**Indstillinger → Notifikationer**, og brug **Send testnotifikation** til at
bekræfte, at det virker.

Notifikationer sendes som standard i **minimal** tilstand: kun overskrift,
kilde, tid og et link til dashboardet. IP-adresser, MAC og porte holdes ude af
mailen og ligger kun bag login. Vælg **Fuld** i Indstillinger, hvis du
eksplicit vil have detaljerne med.

Vil du overvåge noget på dit eget netværk (uptime mod private adresser),
ret i `wrangler.jsonc`:

```jsonc
"vars": { "ALLOW_PRIVATE_TARGETS": "true" }
```

Bemærk: Cloudflare Workers kan ikke nå private adresser alligevel, så
dette er mest relevant for lokal udvikling.

## 5. Byg og deploy

```sh
npm run deploy
```

Det kører `astro build` og derefter `wrangler deploy`. Du får en URL som:

```text
https://sentinel.<dit-subdomæne>.workers.dev
```

Worker-navnet (`sentinel`) kommer fra `wrangler.jsonc` og kan ændres.

## 6. Første besøg og kontolås

Kontooprettelse styres af variablen `ALLOW_BOOTSTRAP`.

- Har du allerede en konto (som nu), lad den stå på `"false"`. Sitet er så låst
  til din eksisterende bruger, og der kan aldrig oprettes flere logins.
- Skal du oprette kontoen for første gang (eller genskabe den): sæt
  `ALLOW_BOOTSTRAP` til `"true"` i `wrangler.jsonc`, kør `npm run deploy`, åbn
  forsiden, vælg brugernavn og en adgangskode på mindst 10 tegn, og sæt den
  derefter tilbage til `"false"` og deploy igen.

Uanset variablen kan kontoen kun oprettes én gang: bootstrap virker kun, mens
der ingen brugere findes (atomisk tjek).

## 7. Eget domæne (valgfrit)

Nemmest via dashboardet: **Workers & Pages → sentinel → Settings →
Domains & Routes → Add custom domain**.

Eller i `wrangler.jsonc` med en route:

```jsonc
"routes": [{ "pattern": "sentinel.ditdomæne.dk", "custom_domain": true }]
```

Deploy igen bagefter.

## 8. Automatisk uptime via Cron Trigger

`sentinel` har et Cron Trigger (`* * * * *`, altså hvert minut) defineret i
`wrangler.jsonc`. Det kalder `scheduled`-handleren i `src/worker.ts`, som kører de
uptime-tjek, hvis interval er udløbet, og gemmer resultatet i D1. Triggeren oprettes
automatisk ved `npm run deploy` og kræver ingen ekstra opsætning.

Hver monitor har sit eget `intervalSec` (minimum 60). Cron kører hvert minut, men
springer monitorer over, hvis interval ikke er nået endnu, så en monitor med 10
minutters interval reelt tjekkes hvert 10. minut.

## 9. Opdateringer

Efter kodeændringer:

```sh
npm run deploy
```

Tilføjer du en ny migration senere (`migrations/0002_....sql`), kør:

```sh
npm run cf-migrate:remote
```

## 10. Daglig lokal udvikling

```sh
npm run cf-migrate:local   # kun første gang (eller efter nye migrationer)
npm run dev                # kører i workerd med lokal D1
```

Den lokale database ligger i `.wrangler/state/` og er ignoreret af git.
For at nulstille lokalt: slet `.wrangler/state/v3/d1` og kør
`npm run cf-migrate:local` igen.

## 11. Fejlfinding

| Symptom | Årsag / løsning |
| --- | --- |
| "no such table: users" | Migrationen er ikke kørt. Kør `cf-migrate:remote` (eller `:local`) |
| `D1-bindingen "DB" mangler` | `wrangler.jsonc` mangler `d1_databases`, eller DB er ikke migreret |
| Login siger "For mange forsøg" | Rate limiting. Vent ~15 min (gemt i D1) |
| E-mail-lækage: "ikke konfigureret" | `HIBP_API_KEY` er ikke sat |
| Deploy klager over `database_id` | Erstat pladsholderen i `wrangler.jsonc` med id fra `d1 create` |
| Vil se live-fejl | `npx wrangler tail` |
| Vil se deployment-historik | `npx wrangler deployments list` |

## 12. Sikkerhedsnoter

- Rate limiting på login gemmes i D1 og virker på tværs af Worker-isolater.
  Til hårde krav kan Cloudflare Rate Limiting / WAF også slås til foran `/api/auth/login`.
- CSP, X-Frame-Options og øvrige sikkerhedsheaders sættes kun i produktion.
- Notekryptering sker i browseren. Kryptering via `crypto.subtle` kræver en
  sikker kontekst (https), hvilket `workers.dev` og eget domæne opfylder.

### Cloudflare Rate Limiting (valgfrit ekstra lag)

Appen har allerede D1-baseret rate limiting på login. Vil du også have et
netværkslag foran, kan du oprette en WAF-regel:

1. Cloudflare Dashboard → dit domæne → **Security → WAF → Rate limiting rules**
2. **Create rule**
3. Udtryk: `http.request.uri.path eq "/api/auth/login" and http.request.method eq "POST"`
4. Rate: fx **10 requests per 1 minute** pr. IP
5. Handling: **Block**, varighed 10 minutter

Det kræver, at du bruger eget domæne (workers.dev-domæner har ikke WAF-regler
på samme måde). Appens egen grænse på 8 forsøg pr. 15. minut gælder uanset.
