# DARKVEDA LAB — homelab control center (Docker)

One `docker compose up` gives you a complete small-lab stack: WireGuard VPN
with a click-to-manage portal, BGP routing (FRR), Samba file sharing with
per-user ACLs, a full IPAM with discovery/topology, and multi-vendor network
device config backups.

```
                        ┌───────────────────────────────┐
                        │  portal :8090  (Flask + Samba) │
                        │  WireGuard peers · BGP ctl     │
                        │  shares + ACLs · backups       │
                        └───────┬───────────────┬───────┘
                                │ volumes       │ 127.0.0.1:9001
                        ┌───────▼───────┐ ┌─────▼─────────┐   ┌────────────┐
                        │ netstack      │ │ ipam :8091    │   │ mariadb    │
                        │ WG · FRR/BGP  │ │ subnets · VLAN │◄─►│  (loopback │
                        │ iptables·br10 │ │ discovery ·    │   │   only)    │
                        └───────────────┘ │ topology ·     │   └────────────┘
                                          │ monitoring     │
                                          └────────────────┘
```

## Services & default logins (demo build)

> ⚠️ **Demo credentials are intentionally trivial so anyone can try it.**
> Change every password before exposing this to the internet or real data.

| Service              | URL / port              | Login              |
| -------------------- | ----------------------- | ------------------ |
| Portal (control UI)  | `http://HOST:8090/`     | `admin` / `admin`  |
| Samba file share     | `\\HOST\lab` (445)      | `admin` / `admin`  |
| IPAM                 | `http://HOST:8091/`     | `admin` / `adminadmin` (app requires ≥ 10 chars) |
| MVNBC backups        | inside portal (MVNBC tab, devices in `mvnbc/`) | n/a |

## Quick start

```bash
git clone https://github.com/Darkveda05/DARKVEDALAB.git
cd DARKVEDALAB
cp .env.example .env          # review it — passwords, subnets, AS numbers
docker compose up -d --build
docker exec darkveda-portal testparm -s   # sanity: samba config valid
```

Then open `http://HOST:8090/` (portal) and `http://HOST:8091/` (IPAM).
Full step-by-step, including WireGuard clients, Samba clients, and the
Zabbix API token for IPAM monitoring, is in **[INSTALL.md](INSTALL.md)**.

## What's inside

| Path                | What                                                      |
| ------------------- | --------------------------------------------------------- |
| `portal/`           | Flask control center + Samba server (Dockerfile included) |
| `netstack/`         | Privileged network plane: WireGuard, FRR/BGP, iptables, br10 |
| `ipam/`             | DarkVeda IPAM app (subnets, VLANs, discovery, topology)   |
| `mvnbc/`            | Multi-vendor device config backup (MikroTik, Cisco, H3C…) |
| `templates/`        | First-boot configs (WireGuard, FRR, Samba, iptables)      |
| `scripts/`          | Lab netns helpers (`ns10-setup.sh`) + uninstall (`uninstall.sh`) |
| `docker-compose.yml`| Wiring: volumes, host networking, healthchecks            |
| `.env.example`      | Every tunable in one place (copy to `.env`)               |

### Portal tabs

WireGuard (tunnel, peers + QR, routes, full `wg0.conf` editor, BGP control,
config backups) · Samba (shares, per-user read/write ACLs, sessions, `smb.conf`
editor) · MVNBC (device backups, compare, schedules, retention) · IPAM
(subnet summary + links to full app) · Backups (one-click snapshots, download,
restore) · Logs (journald + container logs) · Setting (card visibility,
service control with restart + enable/disable).

## How it works

* `netstack` (privileged, host network) owns the kernel pieces: it generates
  the WireGuard server keypair on first boot, renders configs from
  `templates/` + `.env`, creates `br10`, restores the iptables base rules,
  brings up `wg0`, and supervises the FRR daemons (`zebra`, `bgpd`,
  `staticd`, `mgmtd`).
* `portal` (host network, `systemctl` compatibility shim) manages everything
  through the *same* commands as a native install (`wg`, `vtysh`,
  `iptables`, `testparm`, `smbpasswd`) and restarts daemons via supervisord.
  Set `CTL_MODE=systemd` to run it on a host instead.
* Peers are added from the portal (keys generated server-side, QR shown);
  the home/site peer is a regular `[Peer]` with the subnets in AllowedIPs.
* Samba enforces per-user access with `valid users` + `write list` plus
  POSIX ACLs on share folders (no `force user` shortcuts).

## Uninstall

```bash
cd DARKVEDALAB
./scripts/uninstall.sh --help
./scripts/uninstall.sh                        # containers + networks, prompts first
./scripts/uninstall.sh --purge-data --rm-images -y   # also delete keys, DB, shares, images
```

## License

MIT — share and remix freely. You operate it; secure it.
