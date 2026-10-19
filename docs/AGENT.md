# Sentinel-agenten (Proxmox)

En lille lokal scanner, der kører på en maskine **inde i dit eget netværk**
(fx Proxmox-hosten) og uploader fund til Sentinel. Den kører på et fast
interval, afslutter og startes igen af systemd.

> Scan kun netværk du selv ejer. Aktiv scanning af fremmede netværk er ulovligt.

## Hvad den gør

1. Finder hosts i de angivne subnets (ping/ARP eller nmap).
2. Samler MAC, IP, værtsnavn, producent og evt. åbne porte.
3. Uploader resultatet til `POST /api/ingest` med et bearer-token.
4. Serveren opretter deduplikerede hændelser: "ny enhed" og "nye åbne porte".

## Før du starter

- [ ] Proxmox er tændt og kan nå internettet.
- [ ] Du kan logge ind på Proxmox-hosten (SSH eller **Shell** i web-UI'et).
- [ ] **Netværket er bridget til dit LAN.** Dette er det vigtigste punkt.

### Vigtigt om netværk

Agenten skal kunne se de samme enheder som din router. Tjek på Proxmox:

```sh
ip -br a
```

Sammenlign med din routers subnet (fx `192.168.1.x`).

- Ser du samme subnet som resten af hjemmet → fint, du kan fortsætte.
- Ser du et fremmed subnet (fx `10.0.2.x` eller `10.0.0.x`), kører Proxmox
  med **NAT** (typisk hvis det ligger i VirtualBox/VMware med NAT). Så kan
  agenten ikke se dit LAN. Skift VM'ens netværk til **Bridged**, eller kør
  agenten på en maskine der er direkte på LAN'et.
- Kører agenten i en LXC/VM inde i Proxmox, skal den bruge **bridged** netværk
  (`vmbr0`), ikke NAT.

## Trin 1: Opret en agent i Sentinel

Gå til **Indstillinger → Opret agent**. Kopiér tokenet med det samme, det vises
kun én gang. Kun en hash gemmes på serveren.

## Trin 2: Kopiér filerne til Proxmox

Kør på Mac'en (alle tre filer skal med):

```sh
scp ~/sentinel/agent/sentinel-agent.mjs \
    ~/sentinel/agent/nmap-xml.mjs \
    ~/sentinel/agent/install-proxmox.sh \
    root@<proxmox-ip>:/root/
```

## Trin 3: Kør installeren

På Proxmox-hosten:

```sh
cd /root
sudo SENTINEL_URL=https://sentinel.example.workers.dev \
     SENTINEL_TOKEN=<dit-token> \
     SCAN_SUBNETS=192.168.1.0/24 \
     SCANNER=nmap \
     ENABLE_PORT_SCAN=true \
     INTERVAL_MINUTES=10 \
     ./install-proxmox.sh
```

- `SCAN_SUBNETS` skal være det subnet du fandt ovenfor.
- Vil du starte forsigtigt: brug `SCANNER=simple` og `ENABLE_PORT_SCAN=false`
  (kun opdagelse, ingen portscan).
- `INTERVAL_MINUTES` er valgfri (standard 5).

Uden variabler spørger scriptet selv. Det gør følgende:

- installerer Node.js (og nmap, hvis du valgte nmap)
- lægger agenten i `/opt/sentinel`
- gemmer konfigurationen i `/etc/sentinel-agent.env` (kun root kan læse)
- opsætter systemd-service + timer
- laver et første dry-run-scan, så du ser hvad den finder

## Trin 4: Bekræft

```sh
systemctl status sentinel-agent.timer
systemctl list-timers | grep sentinel
journalctl -u sentinel-agent -n 50 --no-pager
```

Inden for et par minutter dukker enhederne op under **Enheder** i Sentinel, og
ukendte enheder i **Hændelser**.

## To scannere: hurtigt og dybt

Installeren opretter to timere:

| Timer | Hvornår | Hvad |
| --- | --- | --- |
| `sentinel-agent.timer` | hvert 15. minut | `nmap -sT -p <10 porte>` (hurtigt, ingen `-sV`) |
| `sentinel-agent-vuln.timer` | dagligt kl. 12:00 | `nmap -sV --script vuln` (dybt) |

Det hyppige scan fanger nye enheder og nye åbne porte på få sekunder. Det
daglige scan opdaterer produkt/version og finder sårbarheder.

Serveren bevarer de kendte versioner, når det hurtige scan (uden `-sV`)
rapporterer tomme versionsfelter, så tjenester ikke ser ud til at ændre sig
frem og tilbage.

Vælg et andet tidspunkt med `VULN_SCAN_TIME=03:00`, og slå den dybe scan fra
med `ENABLE_VULN_SCAN=false`.

Bemærk: Proxmox skal være tændt på det valgte tidspunkt. Timeren har
`Persistent=true`, så en misset scan køres ved næste opstart.

## Sårbarhedsscan

Den dybe scan bruger nmaps indbyggede scripts:

```sh
nmap -sV --script vuln -oX - <subnet>
```

Det er mere aktivt og kan belaste skrøbelige IoT-enheder, så det kører kun én
gang i døgnet (kl. 12:00 som standard):

- `sentinel-agent-vuln.service` (kører agenten med `MODE=vuln`)
- `sentinel-agent-vuln.timer` (`OnCalendar=*-*-* 12:00:00`)

Fund uploades til samme `/api/ingest` og vises under **Sårbarheder**. Du kan
acceptere kendte fund, så de ikke støjer. Den dybe scan uploader også
opdaterede enheder og versioner.

Vil du køre den manuelt:

```sh
MODE=vuln SENTINEL_URL=... SENTINEL_TOKEN=... SCAN_SUBNETS=192.168.1.0/24 \
  node /opt/sentinel/sentinel-agent.mjs --dry-run
```

Fjern `--dry-run` for at uploade.

## Versionsændringer og accepteret baseline

Med `SERVICE_DETECTION=true` gemmer agenten produkt og version. Når en tjeneste
ændrer sig, viser hændelsen en diff, fx:

```
Ændret: port 22/ssh OpenSSH 9.0 → OpenSSH 9.6
```

Under **Enheder** kan du trykke **Accepter baseline**. Så husker Sentinel den
nuværende port- og tjenestetilstand for enheden. Vender enheden tilbage til
den accepterede tilstand efter en udsving, advarer den ikke igen.

## Miljøvariabler

| Variabel            | Påkrævet | Beskrivelse                                                        |
| ------------------- | -------- | ------------------------------------------------------------------ |
| `SENTINEL_URL`      | ja       | Basis-URL, fx `https://sentinel.ditnavn.workers.dev`               |
| `SENTINEL_TOKEN`    | ja       | Token fra Indstillinger                                            |
| `SCAN_SUBNETS`      | nej      | Kommaseparerede CIDR'er, fx `192.168.1.0/24`. Standard: auto      |
| `DHCP_LEASES`       | nej      | Sti eller URL til DHCP-leases (dnsmasq-format eller JSON)          |
| `SCANNER`           | nej      | `simple` (standard) eller `nmap`                                   |
| `ENABLE_PORT_SCAN`  | nej      | `true` for også at tjekke åbne porte                               |
| `PORTS`             | nej      | Kommaseparerede porte (standard: 22,23,53,80,443,445,3389,8080,8443,5900) |
| `SERVICE_DETECTION` | nej      | `true` (kun nmap) tilføjer `-sV` for tjenester/versioner           |
| `NMAP_EXTRA`        | nej      | Ekstra rå nmap-argumenter, fx `-O --osscan-guess`                  |
| `PING_TIMEOUT_MS`   | nej      | Ping-timeout pr. host (standard 800, kun simple)                   |
| `PORT_TIMEOUT_MS`   | nej      | Connect-timeout pr. port (standard 500, kun simple)                |

## Scannere: simple vs nmap

**`SCANNER=simple`** (standard): ping-sweep + ARP-tabellen, valgfrit TCP-connect
mod portlisten. Ingen afhængigheder, ingen root, lav støj.

**`SCANNER=nmap`**: bruger rigtig nmap og parser XML-output. Kræver
`apt install nmap` (installeren gør det automatisk). Uden `ENABLE_PORT_SCAN`
kører den `nmap -sn` (opdagelse). Med `ENABLE_PORT_SCAN=true` kører den
`nmap -sT -p <porte> --open`, og med `SERVICE_DETECTION=true` tilføjes `-sV`.
nmap giver også MAC-producent (`vendor`), så ukendte enheder er nemmere at
genkende.

> **Vigtigt:** nmap skal køre som **root** for at kunne bruge ARP. Kører den
> som en almindelig bruger, falder den tilbage til TCP-ping og finder ikke
> telefoner og andre enheder, der ikke svarer på port 80/443. Installeren
> sætter derfor agenten til at køre som root.

```sh
# Opdagelse med nmap
SCANNER=nmap SCAN_SUBNETS=192.168.1.0/24 node sentinel-agent.mjs

# Portscan + service/version
SCANNER=nmap ENABLE_PORT_SCAN=true PORTS=1-1024 SERVICE_DETECTION=true \
  SCAN_SUBNETS=192.168.1.0/24 node sentinel-agent.mjs

# Ekstra nmap-args
SCANNER=nmap NMAP_EXTRA="-O --osscan-guess" SCAN_SUBNETS=192.168.1.0/24 node sentinel-agent.mjs
```

`-sT` og `-sn` kører uden root. Vil du bruge `-sS`/`-O`, tilføj dem via
`NMAP_EXTRA`, men så skal agenten køre som root.

## DHCP-leases (bedre dækning af trådløse enheder)

Telefoner og IoT-enheder sover og svarer ikke altid på ping. Derfor kan agenten
læse routerens DHCP-leases og inkludere dem, så de ikke "forsvinder" fra
enhedslisten. Sæt `DHCP_LEASES` til en filsti eller en URL:

```sh
# dnsmasq (OpenWrt, de fleste Linux-routere)
DHCP_LEASES=/var/lib/misc/dnsmasq.leases

# eller en URL der returnerer JSON
DHCP_LEASES=https://router.local/leases.json
```

Understøttede formater:

- **dnsmasq:** `<expiry> <mac> <ip> <hostname> <clientid>` (udløbne springes over)
- **JSON:** `[{ "mac": "...", "ip": "...", "hostname": "..." }]` eller `{ "leases": [...] }`

Leases flettes med scan-resultatet. Enheder der kun kendes fra leases får ingen
åbne porte, men tæller som sete, så de ikke udløser "enhed forsvundet".

## Test manuelt (uden upload)

```sh
sudo -u sentinel env $(grep -v '^#' /etc/sentinel-agent.env | xargs) \
  node /opt/sentinel/sentinel-agent.mjs --dry-run
```

Eller direkte fra kilden:

```sh
SENTINEL_URL=https://sentinel.ditnavn.workers.dev \
SENTINEL_TOKEN=<token> \
SCAN_SUBNETS=192.168.1.0/24 \
SCANNER=nmap \
node sentinel-agent.mjs --dry-run
```

## Ændr interval

Rediger `/etc/systemd/system/sentinel-agent.timer` og ændr
`OnUnitActiveSec=5min` til fx `10min`:

```sh
sudo systemctl daemon-reload
sudo systemctl restart sentinel-agent.timer
systemctl list-timers | grep sentinel
```

Ved ny installation kan du bare bruge `INTERVAL_MINUTES=10`.

## Opdater agenten

Kopier de nye filer igen og kør installeren på ny (den er idempotent), eller:

```sh
sudo install -m 0755 sentinel-agent.mjs /opt/sentinel/sentinel-agent.mjs
sudo install -m 0644 nmap-xml.mjs /opt/sentinel/nmap-xml.mjs
sudo systemctl restart sentinel-agent.timer
```

## Slå fra / fjern

```sh
sudo systemctl disable --now sentinel-agent.timer
sudo rm -f /etc/systemd/system/sentinel-agent.{service,timer}
sudo systemctl daemon-reload
```

Slet også agenten i **Indstillinger**, så tokenet ikke længere virker.

## Fejlsøgning

| Problem | Løsning |
| --- | --- |
| `ping: command not found` | `apt install iputils-ping` |
| `nmap: command not found` | `apt install nmap` |
| Ingen enheder dukker op | Tjek at `SCAN_SUBNETS` matcher LAN'et (se "Vigtigt om netværk") |
| Kun Proxmox selv dukker op | Proxmox kører med NAT. Skift til bridged |
| `401` ved upload | Forkert eller slettet token. Lav en ny agent |
| `404` ved upload | Forkert `SENTINEL_URL` (skal være uden `/api/ingest`) |
| Se hvad agenten finder | Kør med `--dry-run` (se ovenfor) |

## Manuel opsætning (uden installer)

`/etc/systemd/system/sentinel-agent.service`:

```ini
[Unit]
Description=Sentinel network agent
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
EnvironmentFile=/etc/sentinel-agent.env
ExecStart=/usr/bin/node /opt/sentinel/sentinel-agent.mjs
```

`/etc/systemd/system/sentinel-agent.timer`:

```ini
[Unit]
Description=Run Sentinel agent every 10 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=10min

[Install]
WantedBy=timers.target
```

`/etc/sentinel-agent.env` (chmod 600):

```sh
SENTINEL_URL=https://sentinel.ditnavn.workers.dev
SENTINEL_TOKEN=<token>
SCAN_SUBNETS=192.168.1.0/24
SCANNER=nmap
ENABLE_PORT_SCAN=true
```

Aktiver:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now sentinel-agent.timer
```

## Noter

- Agenter autentificeres med et token, ikke login. Et lækket token kan kun
  uploade fund, ikke læse noget. Slet agenten i Indstillinger for at spærre den.
- Portscan kan være langsomt på store netværk. Start uden.
- Hosts uden MAC (fx på et routet subnet) får identiteten `ip:<adresse>`.
