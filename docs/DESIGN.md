# Sentinel — designsystem

Mørkt, roligt "control room"-udtryk. Ingen neon. Accenten er en dæmpet cyan-teal,
der signalerer overvågning. Farve betyder altid status, aldrig dekoration.

Kilde til sandhed for tokens er `src/styles/global.css` (`@theme`). Denne fil forklarer
hvorfor de ser ud, som de gør.

## Farver

| Token (CSS)        | Hex       | Rolle                                  |
| ------------------ | --------- | -------------------------------------- |
| `--color-canvas`   | `#0A0E14` | App-baggrund (dybeste lag)             |
| `--color-surface`  | `#121821` | Kort/paneler                           |
| `--color-elevated` | `#1A2230` | Hævede flader, tabel-header, dropdowns |
| `--color-line`     | `#263042` | Standard 1px-kant                      |
| `--color-line-strong` | `#33415A` | Fremhævet kant                     |
| `--color-accent`   | `#2DD4BF` | Primær handling, aktiv nav             |
| `--color-accent-soft` | `#134E4A` | Accent-baggrund                     |
| `--color-success`  | `#34D399` | Status: oppe / løst                    |
| `--color-warn`     | `#FBBF24` | Status: degraderet / udløber snart     |
| `--color-danger`   | `#F87171` | Status: nede / kritisk                 |
| `--color-ink`      | `#E6EDF6` | Primær tekst                           |
| `--color-ink-soft` | `#9FB0C3` | Sekundær tekst                         |
| `--color-ink-muted`| `#64748B` | Labels, metadata                       |

Kontrast: `ink` ≈ 14:1 på canvas, `accent` ≈ 7.9:1, `ink-soft` ≈ 7:1. Alle over AA for
almindelig tekst. `ink-muted` bruges kun til små labels/metadata.

## Typografi

- **UI/tekst:** Inter (Google Fonts), fallback system-stack.
- **Data/kode:** JetBrains Mono til hosts, hashes, IP'er, IDs, tidsstempler og tal i KPI-kort.

| Rolle | Størrelse / line-height | Vægt |
| ----- | ----------------------- | ---- |
| h1    | 24–30px / 1.2           | 600  |
| h2    | 20–24px / 1.25          | 600  |
| h3    | 19px / 1.35             | 600  |
| body  | 15px / 1.6              | 400  |
| small | 13px / 1.5              | 400  |
| mono  | 12–13px / 1.5           | 400  |

## Spacing og radius

- 4px-base: `1=4, 2=8, 3=12, 4=16, 5=20, 6=24, 8=32, 12=48, 16=64`.
- Kort-padding 20px (p-5), sektionsafstand 24px (space-y-6/gap-6).
- Radius: `sm=6px`, `md=10px`, `lg=14px`, samt `full` til badges og status-prikker.
- Skygger bruges næsten ikke. Lag markeres med 1px kant + `bg-elevated`.

## Komponenter

- **Sidebar (240px):** `bg-surface`, højre kant. Ordmærke "Sentinel" i mono. Aktivt punkt
  får `bg-elevated` + 3px accent-streg til venstre. Mobil: nav bliver til pills øverst.
- **Topbar (56px, sticky):** modultitel + breadcrumb i mono til venstre, tidsstempel og
  bruger-chip til højre.
- **KPI-kort** (`StatCard`): label (small, uppercase, muted), tal i mono 28px/600, hint.
  Tynd statusstreg i toppen i tone-farven.
- **Status-badge** (`StatusBadge`): pill, 11px uppercase, baggrund = 12% af farven,
  tekst i fuldmættet farve, 1px kant i farven, valgfri prik.
- **Data-tabel:** header i `bg-elevated` (small uppercase muted), rækker transparente med
  svag `border-line`, hover `bg-canvas`. Host/hash i mono.
- **Knapper:** 36px høje, `radius md`. Primær = accent-baggrund med mørk tekst.
  Sekundær = transparent + kant. Danger = outline i danger-farven.
- **Input:** `bg-canvas`, 1px kant, focus = accent-kant + 3px accent-glow.
- **Panel:** kort med header (titel + evt. actions-slot) og indhold.
- **Empty state:** stiplet kant, dæmpet linje-ikon, titel, én sætning, valgfri CTA.

## Dashboard-layout

Fast venstre-sidebar + sticky topbar. Indholdet er fire KPI-kort øverst, derefter en
bred uptime-tabel og til højre et smalt panel med aktive hændelser og aktiver der udløber
snart. Øjet fanges af de røde/gule status-badges og de fire tal.
