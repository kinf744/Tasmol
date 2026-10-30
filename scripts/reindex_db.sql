-- Réindexe les IDs des comptes Stivaros pour qu'ils soient séquentiels (1..N)
-- à partir de 1. Utile après des suppressions qui laissent des trous dans
-- l'AUTOINCREMENT SQLite.
--
-- Usage : sqlite3 /opt/stivaros/stivaros.db < reindex_db.sql

PRAGMA foreign_keys = OFF;

-- Mapping old_id -> new_id (séquentiel à partir de 1, trié par ancien id)
CREATE TABLE id_map AS
SELECT id AS old_id, ROW_NUMBER() OVER (ORDER BY id) AS new_id FROM users;

-- Nouvelle table users avec mêmes colonnes
CREATE TABLE users_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT UNIQUE NOT NULL,
    phone TEXT NOT NULL,
    name TEXT DEFAULT '',
    activation_code TEXT NOT NULL,
    device_install_id TEXT DEFAULT '',
    app_version TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now')),
    expires_at TEXT,
    active INTEGER DEFAULT 1,
    quota_mb INTEGER DEFAULT 0,
    bytes_used INTEGER DEFAULT 0,
    multi_device INTEGER NOT NULL DEFAULT 0,
    plan TEXT DEFAULT 'BASIC',
    allowed_uuids TEXT DEFAULT ''
);

INSERT INTO users_new (uuid, phone, name, activation_code, device_install_id, app_version, created_at, expires_at, active, quota_mb, bytes_used, multi_device, plan, allowed_uuids)
SELECT u.uuid, u.phone, u.name, u.activation_code, u.device_install_id, u.app_version, u.created_at, u.expires_at, u.active, u.quota_mb, u.bytes_used, u.multi_device, u.plan, u.allowed_uuids
FROM users u
JOIN id_map m ON u.id = m.old_id
ORDER BY m.new_id;

-- Mettre à jour vpn_configs avec les nouveaux user_id
UPDATE vpn_configs SET user_id = (SELECT new_id FROM id_map WHERE old_id = vpn_configs.user_id);

-- Remplacer l'ancienne table
DROP TABLE users;
ALTER TABLE users_new RENAME TO users;

-- Réinitialiser la séquence AUTOINCREMENT
DELETE FROM sqlite_sequence WHERE name='users';
INSERT INTO sqlite_sequence (name, seq) VALUES ('users', (SELECT MAX(id) FROM users));

PRAGMA foreign_keys = ON;

-- Nettoyage
DROP TABLE id_map;

SELECT 'Réindexation terminée : ' || COUNT(*) || ' comptes renumérotés de 1 à ' || MAX(id) AS info FROM users;
