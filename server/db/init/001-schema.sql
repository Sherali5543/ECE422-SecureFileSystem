CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    public_key BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
);

CREATE TABLE IF NOT EXISTS group_members (
    group_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    wrapped_group_key BLOB NOT NULL, -- encrypt(user_priv, group_key)
    PRIMARY KEY (user_id, group_id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (group_id) REFERENCES groups(id)
);

CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path BLOB UNIQUE NOT NULL,
    name BLOB NOT NULL,
    owner_id INTEGER NOT NULL,
    group_id INTEGER,
    mode_bits INTEGER NOT NULL,
    object_type TEXT NOT NULL CHECK (object_type IN ('file', 'directory')),
    wrapped_fek_owner BLOB, -- encrypt(user_priv, file_key)
    wrapped_fek_group BLOB, -- encrypt(group_key, file_key)
    wrapped_fek_other BLOB, -- encrypt(global_key, file_key)
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (owner_id) REFERENCES users(id),
    FOREIGN KEY (group_id) REFERENCES groups(id)
);
