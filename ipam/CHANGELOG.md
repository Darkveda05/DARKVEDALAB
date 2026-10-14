# DarkVeda IPAM

A premium web-based **IP Address Management (IPAM)** and network infrastructure portal, built with **PHP 8.x + MariaDB** per the Enterprise IPAM Portal requirements. Dark-first UI on Bootstrap 5, RBAC, audit trail, IPv4 + IPv6, CSV export, token-authenticated REST API, and Docker-ready deployment.

---













## 5.0.0 — Rack Designer

The Racks section is now a drag-and-drop rack designer, inspired by
[Rackula](https://github.com/RackulaLives/Rackula), built natively on the existing
PHP + MariaDB + Bootstrap stack (no separate service, no rewrite of your data).

- **Drag to mount.** A device library sits beside the rack: generic gear (server,
  switch, router, patch panel, PDU, screen, shelf, blank), every known device model
  with its faceplate, and every unmounted IP record. Drag any of them onto the
  elevation and it snaps to the nearest U.
- **Drag to move, drag the edge to resize.** Units move by grabbing them and resize
  by dragging their top or bottom edge. A live preview shows the target span and
  turns red when it would overlap or run past the rack, so an invalid drop is never
  committed. Works with a mouse or by touch (handy from Termux/tablet on the couch).
- **Real faceplates, front and rear.** Units render the device photo edge-to-edge
  with a legible label overlay; passive gear gets a drawn placeholder appropriate to
  its kind. Front/rear toggle switches the face you're editing.
- **Direct model link.** Rack items can now reference a device model directly
  (`rack_items.device_type_id`), so dragging a model from the library shows its
  faceplate without needing an IP record. See `database/upgrade_5.0.sql`.
- **Inline editing.** Click a unit to open an inspector — label, type, accent colour,
  linked IP, notes, faceplate photo override, or eject — with no page reload. Edits
  save over a small JSON endpoint (`rack_api`) guarded by the usual RBAC + CSRF.
- **Export.** Download the current elevation as PNG or SVG (real faceplates inlined)
  for runbooks and change requests.
- **3D server room unchanged.** The 3D view keeps its look and now reads the same
  richer item model, so anything you design here appears there automatically.

## 4.1.2 — 3D server room rebuilt

- **Proper lighting.** Hemisphere light plus a shadow-casting key light and soft ceiling lamps, on physically
  based materials, so the hardware is actually visible instead of near-black silhouettes.
- **Racks look like racks.** Solid side panels, back and top, a plinth so they stand on the floor, and front
  mounting rails — no more floating wireframe boxes. Dimensions use real measurements (1U = 44.45 mm,
  19" bay), so a 42U rack stands 2.02 m tall next to an 8U at 0.51 m.
- **Devices have depth.** Equipment is inset into the bay with real depth, casts and receives shadows, and
  rear-mounted gear is textured on its rear face. Items without a photo get a drawn faceplate appropriate to
  their kind — patch panels get ports, PDUs get sockets, servers get vents and LEDs.
- **Smooth camera.** Input now moves a target the camera eases toward, so rotate, zoom and pan glide instead
  of snapping. Pitch is clamped so the view can never flip or drop below the floor. Frames render only when
  something changed, so an idle scene costs nothing.
- **A room, not a void.** Textured floor, grid and back wall give the scene depth; rack name labels are
  billboarded sprites that always face the camera.

## 4.1.1

- Rolled back the 4.2 side-by-side elevation; the Front/Rear toggle returns.
- **Rack rows show only the device image, its label and its state dot.** The model and IP address are no
  longer printed across the row — they appear in the hover tooltip along with the U range, so the hardware
  photo stays visible.

## 4.1

- **Device Images section removed** — the standalone page, its navigation entry and route are gone,
  along with the Wikimedia model-image search that lived there.
- **Device photos moved to Devices.** Each device type row now shows its photo, and the edit panel has an
  upload/remove control. Rack elevations and the 3D view still use those photos exactly as before; only the
  online search is gone. Per-unit photo overrides on Racks are unchanged.

## What's new in 4.0

| # | Change | Where |
|---|--------|-------|
| 1 | **Realistic rack elevation** — taller units, rack rails, and the device's real photo used as a full-width faceplate. Units without a photo get a generated panel with vents and a status LED instead of a flat block. | Racks |
| 2 | **Device image library** — search the web for a model photo ("MikroTik RB5009", "Cisco Catalyst 9200"), preview the results, and save one against the device type. Every rack item of that type then shows it automatically; a per-unit override is still possible. Manual upload works too. | Device Images |
| 3 | **3D view shows real devices** — equipment is textured with the same model photos rather than blank panels, with a generated vented faceplate as the fallback. | 3D Server Room |
| 4 | **Backup & Restore simplified** — two cards, two buttons, no wall of text. | Backup & Restore |

### About the image search

Images come from **Wikimedia Commons**, which needs no API key and carries only openly-licensed material —
most image APIs are either paid or return content that cannot legally be copied onto your own server.
Attribution is stored with every image. Nothing is downloaded until you pick a result, and only URLs from
the result set can be fetched, so the feature cannot be pointed at internal addresses.

The server needs outbound HTTPS for this. Without it the page explains the problem and manual upload
still works.

### Upgrading

```bash
mysql -u <user> -p darkveda_ipam < database/upgrade_4.0.sql
```

Adds image columns to `device_types`, a rear-photo column to `rack_items`, and a small search cache.
Idempotent; no existing data is changed.

## What's new in 3.0

| # | Feature | Where |
|---|---------|-------|
| 1 | **Rack editing** — change name, site, RU height and description inline. Shrinking is blocked when mounted gear would end up outside the rack. | Racks |
| 2 | **Passive equipment + photos + multi-U** — mount things that have no IP (patch panels, screens, PDUs, shelves) with an optional PNG/JPG/SVG/WebP photo. Items can span several U: a 2U screen at bottom U9 occupies U9-U10 as one block. Overlaps are rejected with the exact conflicting span. | Racks |
| 3 | **3D server room** — orbit, zoom and pan an immersive scene; click any item for a detail panel with IP, model, serial, OS, CPU/memory and photo. | 3D Server Room |
| 4 | **Monitoring auto-sync** — Off / 5 / 10 / 15 / 30 / 60 minute interval with a live countdown. The choice is stored in the database, so it survives container restarts. | Monitoring |
| 5 | **Web installer** — `public/install.php` checks requirements, tests the database connection, creates the database, imports the schema, creates the administrator and writes `config/config.php`. Self-locks once installed. | install.php |
| 6 | **Backup & restore** — download a `.tar.gz` with a full SQL dump, uploaded files and optionally the config; restore the same archive (or a plain `.sql`) from the browser. The dump is generated in PHP, so `mysqldump` is not required. | Backup & Restore |
| 7 | **Documentation** — attach PDFs, photos, diagrams, manuals, licenses and contracts to any IP record, rack or site, with category filters and search. | Documentation |

### Installing from scratch

Point a browser at `/install.php` and follow the three sections (database, administrator, optional Zabbix).
Delete the file afterwards. The installer refuses to run once an administrator password is set.

### Upgrading from 2.x

```bash
mysql -u <user> -p darkveda_ipam < database/upgrade_3.0.sql
mkdir -p public/uploads && chown -R <web-user> public/uploads
```

Adds `app_settings` and `rack_items`, extends `attachments` with category/title/mime/size/notes, and adds
three permissions. Existing IP-based rack mounts are migrated into `rack_items` automatically. Idempotent.

### File uploads

Photos and documents live in `public/uploads/`. The directory ships with an `.htaccess` that disables PHP
execution; on nginx add the equivalent:

```nginx
location ^~ /uploads/ {
    location ~ \.php$ { return 403; }
}
```

Uploads are validated by detected MIME type rather than filename, stored under generated names, and SVGs
containing scripts or entities are rejected. Documents are always served as downloads with a restrictive
Content-Security-Policy, never rendered in-origin.

## What's new in 2.0

| # | Feature | Where |
|---|---------|-------|
| 1 | **SNMP device discovery (v2c + v3)** — credential profiles with a live test button, optional per-subnet binding. Discovery polls every responding host for sysName, sysDescr, chassis serial, interface MACs and uptime, then fills in hostname / serial / OS / software version automatically. Works alongside the existing ping, ARP, PTR, NetBIOS and mDNS collection. | SNMP Profiles, Discovery |
| 2 | **Network topology from LLDP/CDP** — neighbour tables are walked during each SNMP-enabled scan and stored as edges. Interactive force-directed map with drag, zoom, hover detail and click-through to IP records, plus a filterable neighbour table. | Topology |
| 3 | **Zabbix integration (6.0+ / 7.x)** — bearer-token JSON-RPC client pulling host availability, CPU %, memory % and open problem counts. Status pills appear next to every IP in the subnet view and on rack elevations. Manual sync, connection test, and a cron runner. | Monitoring |
| 4 | **Rack visualization** — clickable U-slot elevations with front/rear faces, multi-U devices sized from their device type, live monitoring dots, and collision-checked mounting. | Racks |
| 5 | **Automation REST API** — endpoints for external systems to keep the IPAM current. | API |

### New API endpoints

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/v1/ips/upsert` | Create-or-update an IP by address. Subnet is matched automatically by containment (or pass `subnet_id` / `subnet_cidr`). Omitted fields are preserved, so partial updates are safe. |
| POST | `/api/v1/monitoring` | Push status: single object or `{"items":[...]}` batch. Fields: `address`, `state` (online/offline/unknown), `cpu_pct`, `memory_pct`, `host_name`, `problem_count`, `uptime_seconds`, `source`. |
| GET | `/api/v1/monitoring` | Current monitoring state for all addresses. |
| GET/POST | `/api/v1/topology` | Read or push LLDP/CDP neighbour edges. |
| GET | `/api/v1/racks` | Racks with their mounted devices and positions. |

All endpoints use `Authorization: Bearer <token>`. Tokens are managed under **Users -> Automation tokens**.

### Configuration

SNMP polling needs the PHP SNMP extension (`apt install php8.3-snmp`, or `apk add php83-snmp` on Alpine/linuxserver images). Without it discovery still runs — only SNMP enrichment and LLDP/CDP topology are skipped, and the SNMP page says so.

Zabbix is configured by environment variable or in `config/config.php` under `'zabbix'`:

```
ZABBIX_URL=https://zabbix.example.com/api_jsonrpc.php
ZABBIX_TOKEN=<Zabbix -> Users -> API tokens>
```

Scheduled jobs:

```
0,30 * * * *  php /path/to/darkveda-ipam/bin/discover.php --all
0,5,10,15,20,25,30,35,40,45,50,55 * * * *  php /path/to/darkveda-ipam/bin/zabbix-sync.php
```

### Upgrading

```bash
mysql -u <user> -p darkveda_ipam < database/upgrade_2.0.sql
```

Adds `snmp_credentials`, `topology_links`, `monitoring_status`; rack placement columns on `ip_addresses`; `snmp_credential_id` on `subnets`; a `description` column on `racks`; and five new permissions. Idempotent; no existing data is modified.

## What's new in 1.5

| # | Change | Where |
|---|--------|-------|
| 1 | **Device search** below the Subnet Utilization card — search by IP address, name (hostname) or serial number; results show status, device type, MAC, serial, OS and software version with links into the subnet view. | Dashboard |
| 2 | **Edit & save for device types** (vendor / model / U-height, inline, with new-vendor creation on the fly). | Devices |
| 3 | **OS and Software version columns** on every IP record — in the assign form, the subnet table (after Serial), the per-IP edit form, CSV export and the REST API (returned on GET, accepted on POST). | Subnets & IPs |
| 4 | **API token UI removed** (page is now just "Users"). The api_tokens table and the REST API bearer auth remain, so previously issued tokens keep working — but new tokens can no longer be created from the UI. To seed one manually if the API is ever needed: INSERT INTO api_tokens (user_id, token_hash, label) VALUES (1, SHA2('your-random-string',256), 'label'); then use the random string as the bearer token. | Users |

### Upgrading

```bash
mysql -u <user> -p darkveda_ipam < database/upgrade_1.5.sql
```

Adds ip_addresses.os and ip_addresses.software_version. Idempotent; no data modified.

## What's new in 1.4

| # | Change | Where |
|---|--------|-------|
| 1 | **Devices moved below VLANs** in the sidebar | Navigation |
| 2 | **Device inventory removed** — the Devices section is now the device **type catalog** only (vendor / model / U-height, with inline vendor creation). The `devices` table stays in the schema for data compatibility. API: `GET /api/v1/devices` replaced by `GET /api/v1/device-types`. | Devices |
| 3 | **IP records now carry the device type and a serial number.** The Device dropdown when assigning or editing an IP lists the types from the Devices section, and a **Serial** column appears after MAC in the subnet view (also in CSV export and the REST API, including on create). | Subnets & IPs |

### Upgrading

```bash
mysql -u <user> -p darkveda_ipam < database/upgrade_1.4.sql
```

Adds `ip_addresses.device_type_id` (FK → device_types, SET NULL) and `ip_addresses.serial_number`. Idempotent; no data modified.

## What's new in 1.3.1 — discovery data quality

Discovery now gathers **MAC addresses and hostnames** much more aggressively during scans:

- **Hostnames** come from three sources tried in order per host: reverse DNS (PTR, honouring `/etc/hosts`), **NetBIOS** node-status queries (answers from Windows and Samba machines), and **mDNS** reverse lookups (answers from Linux, macOS, printers and most IoT gear). NetBIOS and mDNS queries are batched over single UDP sockets, so they add only ~3 seconds to a scan regardless of subnet size.
- **MACs** are merged from every neighbour source available (`ip neigh`, `/proc/net/arp`, `arp -an`), read after a short settle delay.
- The scan summary now reports how many MACs and hostnames were captured, and **warns explicitly when zero MACs were visible** — the usual cause is the scanner sitting behind a bridged/NAT network.

### Important: seeing MACs requires L2 adjacency

ARP only works on the scanner's own network segment. If you run DarkVeda IPAM in Docker with default (bridge) networking, the container is NAT'd and will never see LAN MACs. Options:

1. **Best:** run the container with `network_mode: host` (see the commented line in `docker-compose.yml`), or
2. run `php bin/discover.php --all` via cron directly on a host that lives in the scanned subnet, or
3. accept hostname-only enrichment (NetBIOS/mDNS/PTR still work through routing).

NetBIOS/mDNS resolution needs the PHP `sockets` extension (now enabled in the bundled Dockerfile; on bare metal: `apt install php8.3-sockets` or your distro's equivalent). Without it, discovery degrades gracefully to PTR-only.

## What's new in 1.3

| # | Change | Where |
|---|--------|-------|
| 1 | **IP address conflicts removed** from the dashboard, Discovery page and engine. Discovery still marks hosts as `changed` and notifies admins when a known IP answers with a different MAC — it just no longer maintains a conflicts list. The `ip_conflicts` table stays in the schema; no migration needed. | Dashboard / Discovery |
| 2 | **Edit button on every IP address** (assigned or adopted): status, hostname, device, MAC and description are editable inline; the address itself is immutable (release + re-assign to renumber). MAC format is validated. | Subnet view |
| 3 | **DHCP scopes removed** from the subnet view and controller. The `dhcp_scopes` table stays for data compatibility. | Subnets |

## What's new in 1.2

| # | Change | Where |
|---|--------|-------|
| 1 | Sidebar reordered: Dashboard, Sites, VLANs, Subnets & IPs, Discovery, Devices, Users & Tokens, Audit Log | Navigation |
| 2 | "Top 10 DHCP scopes" widget removed (scopes remain manageable per-subnet) | Dashboard |
| 3 | **Edit** button with inline save form on every Site, VLAN and Subnet (CIDR itself is immutable — recreate to renumber) | Sites / VLANs / Subnets |
| 4 | **Edit** + **Delete** buttons on user accounts: change email, name, role, active flag, reset password. Self-protection: you cannot delete yourself, demote yourself or deactivate yourself. Deleting a user revokes their API tokens; audit history is preserved (attributed to "system"). | Users & Tokens |
| 5 | **VRF module removed** from the UI, REST API, CSV export and navigation. The `vrfs` table and `subnets.vrf_id` column stay in the schema so existing data is untouched — no migration needed for this release. | System-wide |

## What's new in 1.1

| # | Upgrade | Where |
|---|---------|-------|
| 1 | **Top 10 DHCP scopes** widget with utilization bars + **IP address conflicts** widget (MAC mismatches from scans, duplicate MACs, duplicate IPs) | Dashboard |
| 2 | **Expandable subnet rows** — click any subnet on the dashboard to unfold the IP addresses inside (status, hostname, device, MAC, last-seen) | Dashboard |
| 3 | **Sites management** page and **Device types** management (with inline vendor creation) | Sites / Devices |
| 4 | **Discovery engine** — parallel ICMP sweep + ARP + reverse-DNS: detects new devices, auto-fills changed details, alerts admins on unknown hosts, flags MAC/IP conflicts, reports unused-IP candidates. One-click **Adopt** into inventory. | Discovery |

### Discovery usage

- **Web:** *Discovery* page → **Scan now** (IPv4 subnets up to /22, max 1022 hosts, ~5–15 s per /24).
- **Cron:** `php bin/discover.php --all` (or `--subnet=<id>`), e.g. every 30 min:
  `*/30 * * * * php /path/to/darkveda-ipam/bin/discover.php --all`
- MAC addresses come from the local ARP/neighbour table, so scans see MACs only for hosts on the same L2 segment. Run the scanner (or the container with `network_mode: host`) on the network you want inventoried.
- Unknown hosts trigger a notification (bell icon) for every admin.
- "Unused IP candidates" = active records silent for 7+ days in scanned subnets.

### Upgrading an existing 1.0 database

```bash
mysql -u <user> -p darkveda_ipam < database/upgrade_1.1.sql
```

Fresh installs need nothing — `schema.sql` already contains the 1.1 tables.

## Feature coverage (Phase 1 of the requirements roadmap)

| Requirement | Status |
|---|---|
| Auth + RBAC (admin / operator / viewer) | ✅ Sessions, bcrypt, per-permission gating |
| Dashboard | ✅ Stats, subnet utilization, recent activity |
| IP Address Management | ✅ Assign/release, next-free suggestion, in-subnet validation, duplicate protection |
| Subnet Management | ✅ IPv4 + IPv6 CIDR, utilization bars, VLAN/VRF/site linkage |
| VLAN & VRF | ✅ Full CRUD with per-site VLAN uniqueness |
| Device Inventory | ✅ Vendors, device types, sites, status lifecycle |
| Audit Log | ✅ Every create/delete/login/export, filterable |
| REST API | ✅ Bearer-token endpoints (`/api/v1/...`) |
| CSV import/export | ✅ Export (subnets, IPs); import planned |
| Dark mode | ✅ Dark-first with persistent light-mode toggle |
| IPv6 | ✅ Stored as `VARBINARY(16)` via `inet_pton` — sorting & containment work for both families |
| Docker ready | ✅ `docker compose up` with MariaDB 11 |
| 2FA (TOTP) | 🔜 Schema ready (`users.totp_secret`), Phase 2 |
| Rack/DNS/DHCP/Assets | 🔜 Schema in place, UI Phase 2 |
| Discovery/Monitoring/Backups | 🔜 Schema in place, Phase 3 |

The full database schema for **all** modules in the requirements doc (racks, DNS, DHCP, assets, licenses, warranties, config backups, monitoring, notifications, attachments) is already in `database/schema.sql`, so later phases are additive UI work.

## Quick start (Docker)

```bash
docker compose up -d --build

# Set the admin password (required on first run):
docker compose exec app php bin/set-admin-password.php 'YourStrongPassword!'
```

Open **http://localhost:8080** → log in as `admin` with the password you set.

> The seed row for `admin` ships with a placeholder hash on purpose — login is impossible until you run the password script. Never deploy with a known default password.

## Quick start (bare metal)

Requirements: PHP 8.2+ with `pdo_mysql`, MariaDB 10.6+, Apache/Nginx.

```bash
mysql -u root -p < database/schema.sql

# point env vars (or edit config/config.php)
export DB_HOST=127.0.0.1 DB_NAME=darkveda_ipam DB_USER=darkveda DB_PASS=secret

php bin/set-admin-password.php 'YourStrongPassword!'

# dev server (routes /api manually in production web servers):
php -S 0.0.0.0:8080 -t public
```

For Apache, use `docker/apache-vhost.conf` as the reference vhost (docroot = `public/`, alias `/api` → `api/`, and the `SetEnvIf Authorization` line is required for API bearer tokens).

## Project layout

```
darkveda-ipam/
├── public/            # web docroot: front controller + assets
├── api/               # REST API v1 front controller
├── pages/             # views (dashboard, subnets, vlans, vrfs, devices, users, audit)
├── partials/          # layout header/footer (sidebar, topbar, theme toggle)
├── src/               # App, Database (PDO), Auth (RBAC/CSRF/tokens), Audit, IpTools
├── config/config.php  # env-var-driven configuration
├── database/schema.sql
├── bin/set-admin-password.php
├── docker/            # Dockerfile + Apache vhost
└── docker-compose.yml
```

## RBAC model

| Role | Permissions |
|---|---|
| `admin` | everything, incl. `users.manage` |
| `operator` | all IPAM/device read-write, API, audit — no user management |
| `viewer` | read-only dashboard, IPAM, devices |

Permissions are rows in `permissions`, mapped through `role_permissions` — add new modules by inserting a permission and gating with `Auth::requirePermission('x.y')`.

## REST API

Generate a token under **Users & Tokens** (shown once; only its SHA-256 is stored).

```bash
TOKEN=...

# List subnets
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/v1/subnets

# Create a subnet
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"cidr":"10.20.0.0/24","name":"Lab"}' \
  http://localhost:8080/api/v1/subnets

# Auto-assign next free IPv4 in subnet 1
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"address":"auto","hostname":"vm-42"}' \
  http://localhost:8080/api/v1/subnets/1/ips

# Search IPs / hostnames
curl -H "Authorization: Bearer $TOKEN" "http://localhost:8080/api/v1/ips?search=vm-"

# Release an IP
curl -X DELETE -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/v1/ips/7
```

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/v1/subnets` | List subnets with utilization counts |
| POST | `/api/v1/subnets` | Create subnet |
| GET | `/api/v1/subnets/{id}/ips` | List IPs in a subnet |
| POST | `/api/v1/subnets/{id}/ips` | Assign IP (`"address":"auto"` = next free v4) |
| GET | `/api/v1/ips?search=` | Search addresses/hostnames |
| DELETE | `/api/v1/ips/{id}` | Release an IP |
| GET | `/api/v1/vlans` | List VLANs |
| GET | `/api/v1/devices` | List devices |

## Security notes

- All queries use PDO prepared statements; all output is escaped via `e()`.
- CSRF tokens on every state-changing form; session cookies are `HttpOnly` + `SameSite=Lax`.
- Passwords: bcrypt cost 12. API tokens: 256-bit random, stored hashed.
- Set `APP_DEBUG=false` (default) in production; serve over HTTPS so the `secure` cookie flag activates.
- Change the MariaDB passwords in `docker-compose.yml` before any non-local deployment.

## Roadmap alignment

- **Phase 1 (this release):** Auth, Dashboard, IPAM, VLAN/VRF, Devices ✅
- **Phase 2:** Rack elevations, DNS/DHCP UI, assets & warranties, reports, TOTP 2FA
- **Phase 3:** Network discovery, live monitoring, config backups, expanded API
- **Phase 4:** Topology visualization, multi-tenant/SaaS, plugin architecture

---

MIT-style — use, modify, and deploy freely. Built as **DarkVeda IPAM** v1.0.0.
