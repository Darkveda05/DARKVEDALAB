# DarkvedaLab — installation guideline

> Works from a fresh `git clone` — no manual setup beyond `.env`.

Follow top to bottom. Steps marked *(host)* run on the Linux host,
*(portal)* in the web UI at port 8090, *(ipam)* at port 8091.

## 1. Requirements

| Need                 | Minimum / notes                                              |
| -------------------- | ------------------------------------------------------------ |
| Host OS              | Ubuntu 22.04/24.04 (Debian 12 works too), amd64              |
| Kernel               | WireGuard support (`ls /sys/module/wireguard` or ≥ 5.6)      |
| Docker               | Engine ≥ 24 + Compose plugin (`docker compose version`)      |
| RAM / disk           | 2 GB RAM, 10 GB free (MariaDB + backups grow over time)      |
| Network              | A static IP or DynDNS name; UDP **51820** reachable for VPN peers |
| Ports used           | 8090 portal · 8091 IPAM · 51820/udp WireGuard · 445/139 Samba (open to any IP) |

> The `netstack` + `portal` containers use **host networking + privileges**
> because they manage kernel WireGuard, iptables and bridges — the same job
> as a native install, just packaged. Do not run them unprivileged.

## 2. Install from GitHub

```bash
# *(host)* Docker (skip if present)
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER && newgrp docker

# *(host)* Fetch the lab
git clone https://github.com/<your-username>/DarkvedaLab.git && cd DarkvedaLab
cp .env.example .env
nano .env            # <-- set passwords, subnets, public IP
docker compose up -d --build
docker ps --format '{{.Names}}: {{.Status}}'
```

Wait ~60 s on first boot (DB init + key generation), then:

* Portal: `http://HOST:8090/` → `admin` / `admin`
* IPAM: `http://HOST:8091/` → `admin` / `adminadmin`
* **Change all three passwords immediately** (portal `/password`, Samba
  below, IPAM Users page). Demo defaults are public knowledge.
* Logs live under the portal **Logs** tab (app/Samba/WireGuard/kernel) —
  no `journalctl` needed inside the containers.

Check the stack is healthy: portal **Setting → Services Control** should show
everything `active` (use **Start** if anything is down); **WireGuard** tab
should show the tunnel interface with an Enable/Disable button.

## 3. WireGuard setup

### 3.1 Server (automatic)

`netstack` already did this on first boot — verify rather than redo:

```bash
docker exec darkveda-netstack wg show wg0          # interface + peers
docker exec darkveda-netstack cat /etc/wireguard/server_public.key
```

Keys live in the `wgconf` volume (survive `compose down`). To rotate:
delete the volume (`docker volume rm darkvedalab_wgconf` — `darkveda` + folder-name suffix) and recreate —
then re-issue every client config.

### 3.2 Site peer (home router / second site)

1. On the remote side, generate a keypair and note its public key + endpoint.
2. *(portal)* **WireGuard → WireGuard Configuration**: add —
   ```ini
   [Peer]
   PublicKey = <REMOTE-PUBKEY>
   AllowedIPs = 10.99.0.2/32, 172.16.0.0/24, 172.16.30.0/24
   ```
   (list every remote subnet). Save → tunnel restarts (< 10 s drop).
3. On the remote side, mirror with this server's public key
   (`docker exec darkveda-netstack cat /etc/wireguard/server_public.key`)
   and endpoint `YOUR-HOST:51820`, AllowedIPs covering this side
   (`10.99.0.1/32`, `192.168.10.0/24`, …).
4. Verify: `wg show wg0 latest-handshakes` (fresh timestamp), then ping a
   remote subnet address (e.g. the home router) to confirm traffic flows.

### 3.3 Road warriors (phones/laptops)

No manual key handling: *(portal)* **WireGuard → WireGuard Peers → Add peer**
(name + IP or auto) → scan the QR or download the `.conf`.
Per-peer DNS can be set in the same form. To cut a peer off temporarily use
**Connected Peers → Disable** (config is kept, one click to restore); the
**Interfaces** card can stop/start `wg0` itself.

## 4. Samba setup

### 4.1 Server (automatic, then harden)

First boot creates share `[sharelab]` → `./sharelab` on the host
(bind-mounted to `/DATA/sharelab`) with read & write for user `admin/admin`.
Harden now:

1. *(portal)* **Samba → Add User**: create a user per person, ticking
   per-share **No access / Read / Read+Write** — Samba rights *and* folder
   ACLs are applied together.
2. Change the admin Samba password:
   ```bash
   docker exec darkveda-portal bash -c 'echo -e "NEWPASS\nNEWPASS" | smbpasswd -s admin'
   ```
3. Folders: **Add Share** can `mkdir` missing folders (`root:root 2770`,
   access purely via per-user ACLs). Keep share folders under `/DATA`
   (named volume + `./sharelab` bind mount — back them up). The default
   `[sharelab]` folder (`root:root 2770` + `u:admin:rwx` inheritable ACL)
   is created and permissioned automatically on every boot.

How access works: shares use `read only = yes` + `write list` (per-user
write), enforced twice — by Samba at connect time and by POSIX ACLs
(inheritable defaults) at the kernel. No `force user` shortcuts.

### 4.1b Network access (open to any IP)

Shares are reachable from **any IP** — no per-share IP allowlist and no
TCP 445/139 firewall lockdown. Access control is purely per-user
(`valid users` + `write list` + folder ACLs). If you expose 445/139
to the internet, anyone can attempt auth, so use strong Samba passwords.

### 4.2 Clients

* **Windows:** File Explorer address bar → `\\HOST\sharelab` (use the host's
  LAN IP, e.g. `\\192.168.88.10\sharelab`) → enter Samba credentials (`admin`,
  read & write).
  If Windows asks repeatedly: Control Panel → Credential Manager →
  Windows Credentials → add `HOST` with the Samba user/pass.
* **Linux:** `gio mount smb://HOST/sharelab` (GNOME) or
  `sudo mount -t cifs //HOST/sharelab /mnt/sharelab -o username=admin` (Password:
  Samba password, **not** the Linux login).
* **Find the host IP:** on the server `hostname -I`; on the MikroTik
  check DHCP leases. The share is reachable from any IP that can route
  to the host (LAN, `br10`, `wg0`, …) — no firewall allowlist needed.
* **Remote users:** connect WireGuard first, then use the *tunnel* address
  (or use the public IP directly if you intentionally exposed 445/139).
* **Troubleshooting:** `smbclient -L //HOST -U user` (auth + share list);
  `testparm -s` (effective config, must contain no `hosts allow/deny` lines).

## 5. IPAM + Zabbix API key

1. Log in to IPAM (`admin` / `adminadmin`), change the password
   (Users page), fix sites/VLANs/subnets to match your network.
2. *(ipam)* **Monitoring page** for Zabbix:
   1. In **Zabbix**: *Users → API tokens → Create* (read-only user is
      enough) → copy the token.
   2. In **IPAM → Monitoring**: paste *Zabbix URL* (`https://zabbix…/api_jsonrpc.php`)
      + token, **Save & Test** (green = connected).
   3. **Sync now** pulls hosts; matched IPs show online/offline state.
   4. Optional: set auto-sync minutes + Telegram/email alerts (Settings).
3. *(portal)* **IPAM tab** reads the same database (user `darkveda`,
   loopback-only MariaDB) — no extra config if you kept `.env` defaults.

## 6. MVNBC device backups

1. `mvnbc/config/` from the examples:
   `cp devices.conf.example devices.conf` (+ real `vendor,ip,user,pass` lines),
   same for `settings.json` (SMTP/Telegram for alerts).
2. The portal runs `MVNBC.sh` for you (**MVNBC → Run**); cron-style
   scheduling is `docker exec darkveda-portal /opt/mvnbc/MVNBC.sh --auto`.
3. Backups land in `mvnbc/backups/<vendor>/` (git-ignored by design).

## 7. Going live checklist

- [ ] `.env` passwords changed (DB ×2, IPAM admin, portal admin, Samba admin)
- [ ] `templates/` addressing matches YOUR subnets (rebuild after change)
- [ ] UDP 51820 + TCP 8090/8091 reachable as intended; 445/139 open to any IP — firewall it yourself if it must not be public
- [ ] Test: peer handshake fresh · ping remote subnet · `smbclient -L`
- [ ] `docker compose logs --tail 50 netstack portal` shows no errors
- [ ] First snapshot: portal **Backups → Create snapshot now** (+ download copy)

## 8. Troubleshooting

| Symptom | Check |
| --- | --- |
| Portal down | `docker ps`; `docker logs darkveda-portal`; port 8090 free? |
| `wg0` missing | `docker logs darkveda-netstack`; kernel module loaded? |
| No route to remote subnet | Remote peer `AllowedIPs` must list each remote subnet; `wg show wg0 allowed-ips` |
| Samba write denied | Share Access matrix (valid users + write list) **and** folder ACLs — both visible in portal |
| IPAM tab empty | `docker logs darkveda-ipam-db`; DB creds match `.env`? |
| Duplicate portal fight | Only ONE of `darkveda-lab`/`wg-monitor` units may exist — this repo uses compose, remove host units first |

Keep the host units (`smbd`, `wg-quick@wg0`…) **disabled** when running
the Docker lab — two managers for one kernel will fight over ports and routes.
