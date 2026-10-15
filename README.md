# DarkvedaLab — homelab control center (Docker)

One `docker compose up` gives you a complete small-lab stack: a **WireGuard**
VPN with a click-to-manage portal, **Samba** file sharing with per-user ACLs,
a full **IPAM** (subnets, VLANs, discovery, topology), and **multi-vendor
network device config backups** — ready to use right after install, with
demo logins `admin` / `admin`.

```
                        ┌───────────────────────────────┐
                        │  portal :8090  (Flask + Samba) │
                        │  WireGuard · shares + ACLs     │
                        │  backups · services · logs     │
                        └───────┬───────────────┬───────┘
                                │ volumes       │ 127.0.0.1:9001
                        ┌───────▼───────┐ ┌─────▼─────────┐   ┌────────────┐
                        │ netstack      │ │ ipam :8091    │   │ mariadb    │
                        │ WG · br10     │ │ subnets · VLAN │◄─►│  (loopback │
                        │ open firewall │ │ discovery ·    │   │   only)    │
                        └───────────────┘ │ topology ·     │   └────────────┘
                                          │ monitoring     │
                                          └────────────────┘
```

## Prerequisites (read before installing)

| Need | Minimum / notes |
| ---- | --------------- |
| Host OS | Ubuntu 22.04/24.04 (Debian 12 works too), amd64 |
| Kernel | WireGuard support (`ls /sys/module/wireguard`, or kernel ≥ 5.6) |
| Docker | Engine ≥ 24 **+ Compose plugin** (`docker compose version` must work) |
| RAM / disk | 2 GB RAM, 10 GB free (MariaDB + backups grow over time) |
| Network | A static LAN IP; UDP **51820** reachable from wherever VPN peers are |
| Ports used | 8090 portal · 8091 IPAM · 51820/udp WireGuard · 445/139 Samba |

> `netstack` + `portal` run **privileged with host networking** because they
> manage kernel WireGuard, iptables and bridges — the same job as a native
> install, just packaged. Do not run them unprivileged or rootless.

## Quick start (ready to use)

```bash
git clone https://github.com/Darkveda05/DARKVEDALAB.git
cd DARKVEDALAB
cp .env.example .env        # review it — passwords, subnets, timezone
docker compose up -d --build
docker ps --format '{{.Names}}: {{.Status}}'
```

Wait ~60 s on first boot (MariaDB init, WireGuard key generation, Samba
seeding), then open:

| Service | URL | Demo login |
| ------- | --- | ---------- |
| Portal (control UI) | `http://HOST:8090/` | `admin` / `admin` |
| Samba file share | `\\HOST\sharelab` (445) | `admin` / `admin` (read & write) |
| IPAM | `http://HOST:8091/` | `admin` / `adminadmin` (app requires ≥ 10 chars) |

First-boot does everything for you: WireGuard server keypair is generated
(`wgconf` volume), `wg0` comes up with no peers, portal/Samba `admin` accounts
are created, the `[sharelab]` share exists, and the IPAM database is imported
with its admin set from `.env`.

> ⚠️ **Demo credentials are public knowledge — this repo is for learning and
> sharing.** Change every password before exposing anything to the internet
> or storing real data (portal `/password`, Samba `smbpasswd`, IPAM Users
> page, plus `DB_PASS`/`DB_ROOT_PASS` in `.env` followed by a DB rebuild).

Full step-by-step (WireGuard clients, Samba clients, Zabbix token, device
backups) is in **[INSTALL.md](INSTALL.md)**.

## What's inside

| Path | What |
| ---- | ---- |
| `portal/` | Flask control center + Samba server (Dockerfile included) |
| `netstack/` | Privileged network plane: WireGuard, open firewall, `br10` |
| `ipam/` | DarkVeda IPAM app (subnets, VLANs, discovery, topology, monitoring) |
| `mvnbc/` | Multi-vendor device config backup (MikroTik, Cisco, H3C…) |
| `templates/` | First-boot configs (WireGuard, Samba) |
| `sharelab/` | Default file-share folder (bind-mounted, your files stay out of git) |
| `scripts/` | Uninstall (`uninstall.sh`) |
| `docker-compose.yml` | Wiring: volumes, host networking, healthchecks |
| `.env.example` | Every tunable in one place (copy to `.env`) |

### Portal tabs

* **WireGuard** — interface **Enable/Disable**, **Connected Peers** with per-peer
  Enable/Disable, managed road-warrior peers (add/remove, QR + `.conf`
  download), full `wg0.conf` editor with validation + backup.
* **Samba** — shares, users, per-user read/write ACLs, active sessions,
  `smb.conf` editor (validated with `testparm`).
* **MVNBC** — device backups, compare, run-now, schedules, retention, alerts.
* **IPAM** — subnet summary + link into the full app.
* **Backups** — one-click snapshots of all configs, download & restore.
* **Logs** — supervisor/app/Samba logs, WireGuard + kernel (dmesg).
* **Setting** — card visibility, **Services Control** (Start/Stop/Restart per
  service and container).

## How it works

* `netstack` (privileged, host network) owns the kernel pieces: generates the
  WireGuard server keypair on first boot, renders `wg0.conf` from `templates/`
  + `.env`, creates `br10`, applies an **open** firewall (ACCEPT policies,
  Docker chains untouched) and brings up `wg0`.
* `portal` (host network, `systemctl` compatibility shim) manages everything
  through the same commands as a native install (`wg`, `iptables`, `testparm`,
  `smbpasswd`) and supervises daemons locally. Set `CTL_MODE=systemd` to run
  it on a host instead.
* Peers are added from the portal (keys generated server-side, QR shown).
  Disabling a peer comments it out of `wg0.conf` (kept, one click to restore);
  deleting removes it permanently.
* Samba enforces per-user access with `valid users` + `write list` plus POSIX
  ACLs on share folders (no `force user` shortcuts).
* Nothing secret ships in this repo: `.env`, keys, databases, peer configs
  and backups are all git-ignored — only `*.example` templates with dummy
  values are committed.

## Going live checklist

- [ ] `.env` passwords changed (DB ×2, IPAM admin, portal admin, Samba admin)
- [ ] `templates/` addressing matches YOUR subnets (rebuild after change)
- [ ] UDP 51820 + TCP 8090/8091 reachable as intended; 445/139 is open to any
      IP by design — firewall it yourself if it must not be public
- [ ] Test: peer handshake fresh · ping remote subnet · `smbclient -L`
- [ ] `docker compose logs --tail 50 netstack portal` shows no errors
- [ ] First snapshot: portal **Backups → Create snapshot now** (+ download copy)

## Uninstall

```bash
cd DARKVEDALAB
chmod +x scripts/uninstall.sh
./scripts/uninstall.sh --help
./scripts/uninstall.sh                        # containers + networks, prompts first
./scripts/uninstall.sh --purge-data --rm-images -y   # also delete keys, DB, shares, images
```

* Default keeps volumes/images and skips `wg0`/`br10`/iptables cleanup while
  native host units (`wg-quick@wg0`, `smbd`) are active.
* `--purge-data` deletes WireGuard keys, Samba state, shares, portal data, DB.
* `--force-host-net` takes down live `wg0`/`br10`/iptables too (drops VPN).

## License

MIT — share and remix freely. You operate it; secure it.
