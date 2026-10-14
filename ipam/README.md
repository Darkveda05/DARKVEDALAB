# DarkVeda IPAM

Self-hosted **IP Address Management** for homelabs and small networks — with
automatic discovery, network topology, rack visualisation and live monitoring.

Built with PHP 8.3 + MariaDB. No Composer, no build step, no JavaScript
framework. Runs in one container.

![License](https://img.shields.io/badge/license-MIT-blue)
![PHP](https://img.shields.io/badge/PHP-8.1%2B-777bb4)
![Docker](https://img.shields.io/badge/docker-ghcr.io-2496ed)

---

## Features

| | |
|---|---|
| **IPAM** | Subnets, IPv4, VLANs, sites, next-free-address suggestions, CSV export |
| **Discovery** | Parallel ping sweep, ARP, reverse DNS, NetBIOS and mDNS name resolution, plus **SNMP v2c/v3** polling for sysName, OS/version, chassis serial and interface MACs |
| **Topology** | **LLDP and CDP** neighbours collected over SNMP, rendered as an interactive force-directed map |
| **Racks** | Front/rear elevations with real device photos, multi-U devices, passive gear (patch panels, screens, PDUs), plus a **3D server room** with lit, shadowed racks you can orbit and click |
| **Monitoring** | **Zabbix 6.0+/7.x** integration — online/offline, CPU and memory shown next to every IP, with configurable auto-sync |
| **Documentation** | Attach PDFs, diagrams, manuals, licenses and contracts to any device, rack or site |
| **Operations** | Role-based access control, audit log, backup & restore, REST API for automation |

## Quick start

```bash
git clone https://github.com/darkveda05/darkveda-ipam.git
cd darkveda-ipam
cp .env.example .env
nano .env                 # set ADMIN_PASSWORD
docker compose up -d
```

Open <http://localhost:8080> and sign in as **`admin`** with the
`ADMIN_PASSWORD` you set. Remove that variable from `.env` afterwards — it is
only read at startup.

The container creates its schema on first boot and applies any pending
upgrades automatically, so there is nothing to import by hand.


## Configuration

Everything is set with environment variables — see [`.env.example`](.env.example).

| Variable | Default | Purpose |
|---|---|---|
| `DB_HOST` `DB_PORT` `DB_NAME` `DB_USER` `DB_PASS` | `db` `3306` `darkveda_ipam` `darkveda` — | Database connection |
| `ADMIN_PASSWORD` | — | Sets the `admin` password at startup; min 10 characters |
| `APP_TZ` | `UTC` | Timezone |
| `APP_DEBUG` | `false` | Verbose errors — never enable in production |
| `ZABBIX_URL` `ZABBIX_TOKEN` | — | Monitoring integration; can also be set in the UI |


## Zabbix Integration

Create the token in Zabbix:
1. Open Zabbix at http://<zabbix ip>/zabbix
2. Users → API tokens → Create API token (top right)
3. Name: darkveda-ipam
4. User: pick the account it acts as — the token inherits that user's permissions exactly. A read-only user is safer than Admin, since IPAM only ever reads.
5. Set expiration date: uncheck it unless you want to rotate manually
6. Add — the token string appears once on the confirmation screen. Copy it now; you can only regenerate it later.


If you're running the Docker version <http://localhost:8080>, use environment variables. In .env:
```
ZABBIX_URL=http://<zabbix ip>/zabbix/api_jsonrpc.php
ZABBIX_TOKEN=paste-the-token-here
ZABBIX_VERIFY_TLS=true
```

Then recreate the container so it picks them up:
``` bash
docker compose up -d
```

## Security notes

- `config/config.php` and `.env` are git-ignored and hold credentials.
- Give the Zabbix integration a **read-only** API user; it only ever reads.


## Contributing

Issues and pull requests are welcome.

## License

MIT — see [LICENSE](LICENSE).
