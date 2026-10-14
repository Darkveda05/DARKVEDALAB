-- ============================================================
--  DarkVeda IPAM — MariaDB Schema
--  Requires MariaDB 10.6+ / MySQL 8.0+
-- ============================================================

CREATE DATABASE IF NOT EXISTS darkveda_ipam
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE darkveda_ipam;

SET FOREIGN_KEY_CHECKS = 0;

-- ------------------------------------------------------------
-- Auth / RBAC
-- ------------------------------------------------------------
CREATE TABLE roles (
  id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name        VARCHAR(50) NOT NULL UNIQUE,
  description VARCHAR(255) NULL
) ENGINE=InnoDB;

CREATE TABLE permissions (
  id   INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(80) NOT NULL UNIQUE
) ENGINE=InnoDB;

CREATE TABLE role_permissions (
  role_id       INT UNSIGNED NOT NULL,
  permission_id INT UNSIGNED NOT NULL,
  PRIMARY KEY (role_id, permission_id),
  FOREIGN KEY (role_id)       REFERENCES roles(id)       ON DELETE CASCADE,
  FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE users (
  id            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  username      VARCHAR(64)  NOT NULL UNIQUE,
  email         VARCHAR(190) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  full_name     VARCHAR(120) NULL,
  role_id       INT UNSIGNED NOT NULL,
  is_active     TINYINT(1)   NOT NULL DEFAULT 1,
  totp_secret   VARCHAR(64)  NULL,          -- reserved for 2FA (Phase 2)
  last_login_at DATETIME     NULL,
  created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (role_id) REFERENCES roles(id)
) ENGINE=InnoDB;

CREATE TABLE api_tokens (
  id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id    INT UNSIGNED NOT NULL,
  token_hash CHAR(64)     NOT NULL UNIQUE,   -- sha256 of token
  label      VARCHAR(80)  NOT NULL,
  last_used  DATETIME     NULL,
  created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- Physical hierarchy: sites → buildings → rooms → racks
-- ------------------------------------------------------------
CREATE TABLE sites (
  id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name        VARCHAR(120) NOT NULL UNIQUE,
  slug        VARCHAR(64)  NOT NULL UNIQUE,
  address     VARCHAR(255) NULL,
  description VARCHAR(255) NULL,
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE buildings (
  id      INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  site_id INT UNSIGNED NOT NULL,
  name    VARCHAR(120) NOT NULL,
  FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE rooms (
  id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  building_id INT UNSIGNED NOT NULL,
  name        VARCHAR(120) NOT NULL,
  FOREIGN KEY (building_id) REFERENCES buildings(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE racks (
  id       INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  room_id  INT UNSIGNED NULL,
  site_id  INT UNSIGNED NOT NULL,
  name     VARCHAR(120) NOT NULL,
  u_height SMALLINT UNSIGNED NOT NULL DEFAULT 42,
  description VARCHAR(255) NULL,
  FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE SET NULL,
  FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- Device inventory
-- ------------------------------------------------------------
CREATE TABLE vendors (
  id   INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(120) NOT NULL UNIQUE
) ENGINE=InnoDB;

CREATE TABLE device_types (
  id        INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  vendor_id INT UNSIGNED NULL,
  model     VARCHAR(120) NOT NULL,
  u_height  SMALLINT UNSIGNED NOT NULL DEFAULT 1,
  image_path   VARCHAR(255) NULL,
  image_source VARCHAR(255) NULL,
  image_credit VARCHAR(255) NULL,
  FOREIGN KEY (vendor_id) REFERENCES vendors(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE devices (
  id             INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name           VARCHAR(120) NOT NULL,
  device_type_id INT UNSIGNED NULL,
  site_id        INT UNSIGNED NULL,
  rack_id        INT UNSIGNED NULL,
  rack_position  SMALLINT UNSIGNED NULL,
  serial_number  VARCHAR(120) NULL,
  asset_tag      VARCHAR(120) NULL,
  status         ENUM('active','planned','staged','failed','offline','decommissioned')
                 NOT NULL DEFAULT 'active',
  mgmt_ip        VARCHAR(45)  NULL,
  notes          TEXT NULL,
  created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (device_type_id) REFERENCES device_types(id) ON DELETE SET NULL,
  FOREIGN KEY (site_id)        REFERENCES sites(id)        ON DELETE SET NULL,
  FOREIGN KEY (rack_id)        REFERENCES racks(id)        ON DELETE SET NULL,
  INDEX idx_devices_name (name)
) ENGINE=InnoDB;

CREATE TABLE interfaces (
  id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  device_id   INT UNSIGNED NOT NULL,
  name        VARCHAR(80) NOT NULL,
  mac_address CHAR(17) NULL,
  description VARCHAR(255) NULL,
  FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE,
  UNIQUE KEY uq_iface (device_id, name)
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- L2 / L3: VRFs, VLANs, subnets, IPs (IPv4 + IPv6)
-- ------------------------------------------------------------
CREATE TABLE vrfs (
  id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name        VARCHAR(120) NOT NULL UNIQUE,
  rd          VARCHAR(64)  NULL COMMENT 'Route distinguisher',
  description VARCHAR(255) NULL
) ENGINE=InnoDB;

CREATE TABLE vlans (
  id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  site_id     INT UNSIGNED NULL,
  vid         SMALLINT UNSIGNED NOT NULL,
  name        VARCHAR(120) NOT NULL,
  description VARCHAR(255) NULL,
  status      ENUM('active','reserved','deprecated') NOT NULL DEFAULT 'active',
  FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE SET NULL,
  UNIQUE KEY uq_vlan (site_id, vid)
) ENGINE=InnoDB;

CREATE TABLE subnets (
  id           INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  cidr         VARCHAR(64)   NOT NULL COMMENT 'e.g. 10.0.0.0/24 or 2001:db8::/64',
  network_bin  VARBINARY(16) NOT NULL COMMENT 'inet_pton of network address',
  prefix_len   TINYINT UNSIGNED NOT NULL,
  ip_version   TINYINT UNSIGNED NOT NULL DEFAULT 4,
  name         VARCHAR(120)  NULL,
  vlan_id      INT UNSIGNED  NULL,
  vrf_id       INT UNSIGNED  NULL,
  site_id      INT UNSIGNED  NULL,
  gateway      VARCHAR(45)   NULL,
  status       ENUM('active','reserved','deprecated','container') NOT NULL DEFAULT 'active',
  description  VARCHAR(255)  NULL,
  snmp_credential_id INT UNSIGNED NULL,
  created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (vlan_id) REFERENCES vlans(id) ON DELETE SET NULL,
  FOREIGN KEY (vrf_id)  REFERENCES vrfs(id)  ON DELETE SET NULL,
  FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE SET NULL,
  UNIQUE KEY uq_subnet (network_bin, prefix_len, vrf_id)
) ENGINE=InnoDB;

CREATE TABLE ip_addresses (
  id           INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  subnet_id    INT UNSIGNED  NOT NULL,
  address      VARCHAR(45)   NOT NULL,
  address_bin  VARBINARY(16) NOT NULL,
  status       ENUM('active','reserved','dhcp','deprecated','gateway') NOT NULL DEFAULT 'active',
  hostname     VARCHAR(190)  NULL,
  device_id    INT UNSIGNED  NULL,
  interface_id INT UNSIGNED  NULL,
  mac_address  CHAR(17)      NULL,
  device_type_id INT UNSIGNED NULL,
  serial_number  VARCHAR(120) NULL,
  os               VARCHAR(120) NULL,
  software_version VARCHAR(120) NULL,
  rack_id       INT UNSIGNED NULL,
  rack_position SMALLINT UNSIGNED NULL,
  rack_face     ENUM('front','rear') NOT NULL DEFAULT 'front',
  last_seen   DATETIME NULL,
  description  VARCHAR(255)  NULL,
  created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (subnet_id)    REFERENCES subnets(id)    ON DELETE CASCADE,
  FOREIGN KEY (device_id)    REFERENCES devices(id)    ON DELETE SET NULL,
  FOREIGN KEY (interface_id) REFERENCES interfaces(id) ON DELETE SET NULL,
  FOREIGN KEY (device_type_id) REFERENCES device_types(id) ON DELETE SET NULL,
  UNIQUE KEY uq_ip (subnet_id, address_bin),
  INDEX idx_ip_bin (address_bin)
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- DNS / DHCP
-- ------------------------------------------------------------
CREATE TABLE dns_records (
  id      INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name    VARCHAR(190) NOT NULL,
  type    ENUM('A','AAAA','CNAME','MX','TXT','PTR','SRV','NS') NOT NULL,
  content VARCHAR(255) NOT NULL,
  ttl     INT UNSIGNED NOT NULL DEFAULT 3600,
  ip_id   INT UNSIGNED NULL,
  FOREIGN KEY (ip_id) REFERENCES ip_addresses(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE dhcp_reservations (
  id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  subnet_id   INT UNSIGNED NOT NULL,
  mac_address CHAR(17)     NOT NULL,
  ip_id       INT UNSIGNED NULL,
  hostname    VARCHAR(190) NULL,
  FOREIGN KEY (subnet_id) REFERENCES subnets(id)      ON DELETE CASCADE,
  FOREIGN KEY (ip_id)     REFERENCES ip_addresses(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- Assets / lifecycle
-- ------------------------------------------------------------
CREATE TABLE assets (
  id             INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  device_id      INT UNSIGNED NULL,
  name           VARCHAR(190) NOT NULL,
  purchase_date  DATE NULL,
  purchase_price DECIMAL(12,2) NULL,
  notes          TEXT NULL,
  FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE licenses (
  id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name       VARCHAR(190) NOT NULL,
  vendor_id  INT UNSIGNED NULL,
  license_key VARCHAR(255) NULL,
  expires_on DATE NULL,
  seats      INT UNSIGNED NULL,
  FOREIGN KEY (vendor_id) REFERENCES vendors(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE warranties (
  id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  device_id  INT UNSIGNED NOT NULL,
  provider   VARCHAR(190) NULL,
  expires_on DATE NULL,
  FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- Ops: config backups, monitoring (Phase 3 placeholders)
-- ------------------------------------------------------------
CREATE TABLE config_backups (
  id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  device_id  INT UNSIGNED NOT NULL,
  taken_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  config     MEDIUMTEXT NOT NULL,
  checksum   CHAR(64) NULL,
  FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE monitoring_results (
  id         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  device_id  INT UNSIGNED NOT NULL,
  checked_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  status     ENUM('up','down','degraded') NOT NULL,
  latency_ms DECIMAL(8,2) NULL,
  FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE,
  INDEX idx_mon_dev_time (device_id, checked_at)
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- Audit / notifications / attachments
-- ------------------------------------------------------------
CREATE TABLE audit_logs (
  id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id     INT UNSIGNED NULL,
  action      VARCHAR(40)  NOT NULL,      -- create|update|delete|login|logout|export
  entity_type VARCHAR(60)  NOT NULL,
  entity_id   VARCHAR(60)  NULL,
  details     TEXT NULL,
  ip_address  VARCHAR(45)  NULL,
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
  INDEX idx_audit_time (created_at)
) ENGINE=InnoDB;

CREATE TABLE notifications (
  id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id    INT UNSIGNED NOT NULL,
  message    VARCHAR(255) NOT NULL,
  is_read    TINYINT(1)   NOT NULL DEFAULT 0,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE attachments (
  id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  entity_type VARCHAR(60)  NOT NULL,
  entity_id   INT UNSIGNED NOT NULL,
  category    VARCHAR(40)  NOT NULL DEFAULT 'document',
  title       VARCHAR(190) NULL,
  filename    VARCHAR(255) NOT NULL,
  stored_path VARCHAR(255) NOT NULL,
  mime_type   VARCHAR(120) NULL,
  size_bytes  INT UNSIGNED NULL,
  notes       VARCHAR(255) NULL,
  uploaded_by INT UNSIGNED NULL,
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_attach_entity (entity_type, entity_id),
  FOREIGN KEY (uploaded_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

SET FOREIGN_KEY_CHECKS = 1;

-- ============================================================
-- Seed data
-- ============================================================

-- ------------------------------------------------------------
-- DHCP scopes & Discovery engine (v1.1)
-- ------------------------------------------------------------
CREATE TABLE dhcp_scopes (
  id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  subnet_id       INT UNSIGNED NOT NULL,
  name            VARCHAR(120) NOT NULL,
  range_start     VARCHAR(45)  NOT NULL,
  range_end       VARCHAR(45)  NOT NULL,
  range_start_bin VARBINARY(16) NOT NULL,
  range_end_bin   VARBINARY(16) NOT NULL,
  lease_time      INT UNSIGNED NOT NULL DEFAULT 86400,
  server          VARCHAR(190) NULL,
  is_active       TINYINT(1)   NOT NULL DEFAULT 1,
  description     VARCHAR(255) NULL,
  created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (subnet_id) REFERENCES subnets(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE discovery_runs (
  id            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  subnet_id     INT UNSIGNED NOT NULL,
  started_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  finished_at   DATETIME NULL,
  hosts_scanned INT UNSIGNED NOT NULL DEFAULT 0,
  hosts_alive   INT UNSIGNED NOT NULL DEFAULT 0,
  new_hosts     INT UNSIGNED NOT NULL DEFAULT 0,
  changed_hosts INT UNSIGNED NOT NULL DEFAULT 0,
  triggered_by  INT UNSIGNED NULL,
  FOREIGN KEY (subnet_id)    REFERENCES subnets(id) ON DELETE CASCADE,
  FOREIGN KEY (triggered_by) REFERENCES users(id)   ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE discovered_hosts (
  id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  subnet_id   INT UNSIGNED NOT NULL,
  address     VARCHAR(45)  NOT NULL,
  address_bin VARBINARY(16) NOT NULL,
  mac_address CHAR(17)     NULL,
  hostname    VARCHAR(190) NULL,
  status      ENUM('new','known','changed') NOT NULL DEFAULT 'new',
  first_seen  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_run_id INT UNSIGNED NULL,
  adopted     TINYINT(1) NOT NULL DEFAULT 0,
  UNIQUE KEY uq_dh_subnet_addr (subnet_id, address_bin),
  FOREIGN KEY (subnet_id)   REFERENCES subnets(id)        ON DELETE CASCADE,
  FOREIGN KEY (last_run_id) REFERENCES discovery_runs(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE ip_conflicts (
  id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  subnet_id   INT UNSIGNED NULL,
  address     VARCHAR(45)  NOT NULL,
  kind        ENUM('mac_mismatch','duplicate_mac','duplicate_ip') NOT NULL,
  expected    VARCHAR(190) NULL,
  seen        VARCHAR(190) NULL,
  detected_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  resolved    TINYINT(1) NOT NULL DEFAULT 0,
  resolved_at DATETIME NULL,
  FOREIGN KEY (subnet_id) REFERENCES subnets(id) ON DELETE CASCADE
) ENGINE=InnoDB;



-- ------------------------------------------------------------
-- SNMP / topology / monitoring (v2.0)
-- ------------------------------------------------------------
CREATE TABLE snmp_credentials (
  id            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name          VARCHAR(120) NOT NULL,
  version       ENUM('2c','3') NOT NULL DEFAULT '2c',
  community     VARCHAR(190) NULL,              -- v2c
  sec_name      VARCHAR(190) NULL,              -- v3
  sec_level     ENUM('noAuthNoPriv','authNoPriv','authPriv') NULL,
  auth_protocol ENUM('MD5','SHA','SHA256','SHA512') NULL,
  auth_pass     VARCHAR(190) NULL,
  priv_protocol ENUM('DES','AES','AES256') NULL,
  priv_pass     VARCHAR(190) NULL,
  timeout_us    INT UNSIGNED NOT NULL DEFAULT 1000000,
  retries       TINYINT UNSIGNED NOT NULL DEFAULT 1,
  is_default    TINYINT(1) NOT NULL DEFAULT 0,
  created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_snmp_name (name)
) ENGINE=InnoDB;

CREATE TABLE topology_links (
  id             INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  protocol       ENUM('lldp','cdp','fdb','arp') NOT NULL,
  local_ip       VARCHAR(45)  NOT NULL,
  local_name     VARCHAR(190) NULL,
  local_port     VARCHAR(190) NULL,
  remote_name    VARCHAR(190) NULL,
  remote_port    VARCHAR(190) NULL,
  remote_ip      VARCHAR(45)  NULL,
  remote_descr   VARCHAR(255) NULL,
  first_seen     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_link (protocol, local_ip, local_port, remote_name, remote_port),
  INDEX idx_link_local (local_ip)
) ENGINE=InnoDB;

CREATE TABLE monitoring_status (
  id             INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  address        VARCHAR(45) NOT NULL,
  source         VARCHAR(40) NOT NULL DEFAULT 'zabbix',
  state          ENUM('online','offline','unknown') NOT NULL DEFAULT 'unknown',
  cpu_pct        DECIMAL(5,2) NULL,
  memory_pct     DECIMAL(5,2) NULL,
  uptime_seconds BIGINT UNSIGNED NULL,
  host_name      VARCHAR(190) NULL,
  problem_count  INT UNSIGNED NOT NULL DEFAULT 0,
  checked_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_mon_addr (address)
) ENGINE=InnoDB;


-- ------------------------------------------------------------
-- Settings, rack items, documentation (v3.0)
-- ------------------------------------------------------------
CREATE TABLE app_settings (
  skey       VARCHAR(80) PRIMARY KEY,
  sval       TEXT NULL,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE rack_items (
  id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  rack_id     INT UNSIGNED NOT NULL,
  ip_id       INT UNSIGNED NULL,
  device_type_id INT UNSIGNED NULL,
  name        VARCHAR(160) NOT NULL,
  kind        VARCHAR(40)  NOT NULL DEFAULT 'device',
  u_position  SMALLINT UNSIGNED NOT NULL,
  u_size      SMALLINT UNSIGNED NOT NULL DEFAULT 1,
  face        ENUM('front','rear') NOT NULL DEFAULT 'front',
  color       VARCHAR(20)  NULL,
  photo_path  VARCHAR(255) NULL,
  photo_rear  VARCHAR(255) NULL,
  description VARCHAR(255) NULL,
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (rack_id) REFERENCES racks(id) ON DELETE CASCADE,
  FOREIGN KEY (ip_id)   REFERENCES ip_addresses(id) ON DELETE SET NULL,
  CONSTRAINT fk_rack_items_device_type
    FOREIGN KEY (device_type_id) REFERENCES device_types(id) ON DELETE SET NULL,
  INDEX idx_rack_items_rack (rack_id, face, u_position)
) ENGINE=InnoDB;


CREATE TABLE model_image_cache (
  id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  query      VARCHAR(190) NOT NULL,
  results    MEDIUMTEXT NULL,
  fetched_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_mic_query (query)
) ENGINE=InnoDB;

INSERT INTO roles (name, description) VALUES
  ('admin',    'Full access to all modules'),
  ('operator', 'Read/write on IPAM data, no user management'),
  ('viewer',   'Read-only access');

INSERT INTO permissions (name) VALUES
  ('dashboard.view'),
  ('ipam.view'), ('ipam.manage'),
  ('devices.view'), ('devices.manage'),
  ('users.manage'),
  ('audit.view'),
  ('api.access'),
  ('discovery.view'), ('discovery.run'),
  ('topology.view'), ('racks.view'), ('racks.manage'), ('monitoring.view'), ('snmp.manage'),
  ('docs.view'), ('docs.manage'), ('backup.manage');

-- admin: everything
INSERT INTO role_permissions (role_id, permission_id)
  SELECT 1, id FROM permissions;
-- operator: everything except users.manage
INSERT INTO role_permissions (role_id, permission_id)
  SELECT 2, id FROM permissions WHERE name <> 'users.manage';
-- viewer: view-only
INSERT INTO role_permissions (role_id, permission_id)
  SELECT 3, id FROM permissions WHERE name IN ('dashboard.view','ipam.view','devices.view','discovery.view','topology.view','racks.view','monitoring.view','docs.view');

-- Default admin — username: admin / password: DarkVeda@123  (CHANGE THIS)
INSERT INTO users (username, email, password_hash, full_name, role_id) VALUES
  ('admin', 'admin@darkveda.local',
   '$2y$10$PLACEHOLDER_HASH_REPLACED_BY_INSTALLER',
   'DarkVeda Administrator', 1);

INSERT INTO sites (name, slug, address, description) VALUES
  ('Lab HQ', 'lab-hq', 'Demo site (edit me)', 'Primary site');

INSERT INTO vendors (name) VALUES ('Cisco'), ('Juniper'), ('MikroTik'), ('Ubiquiti'), ('HPE Aruba');

INSERT INTO vrfs (name, rd, description) VALUES
  ('default', NULL, 'Global routing table');

INSERT INTO vlans (site_id, vid, name, description) VALUES
  (1, 10, 'MGMT',    'Management network'),
  (1, 20, 'SERVERS', 'Server farm'),
  (1, 30, 'USERS',   'User access');

INSERT INTO app_settings (skey, sval) VALUES
  ('monitoring_auto_sync_minutes', '0'),
  ('image_search_enabled', '1'),
  ('image_search_provider', 'wikimedia'),
  ('installed_version', '3.0.0');
