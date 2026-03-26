# CLI Guide

This guide shows how to run the Secure File System client and server, what commands the CLI supports, and a few copy-paste demo flows.

## Start The Project

From the repo root:

```bash
make all
./build/server/server
```

In a second terminal:

```bash
./build/client/client
```

The project now has sensible defaults, so you do not need to set environment variables for a normal local run.

## Main Menu

When the client starts, you will see:

```text
login
register
exit
```

Use:

- `register` to create a new user
- `login` to authenticate and enter the file-system CLI
- `exit` to quit the client

## CLI Commands

After login, the client supports these commands:

```text
pwd
ls [path]
cd <path>
mkdir <path>
create <remote_path> [group_name]
write <remote_path> <text>
read <remote_path>
rm <remote_path>
mv <source_path> <destination_path>
chmod <mode_bits> <remote_path>
group-create <group_name>
group-add <group_name> <username>
group-rm <group_name> <username>
group-list [username]
group-key <group_name>
help
logout
```

## Command Notes

### Navigation

- `pwd`
  Prints the current working directory.
- `ls [path]`
  Lists the current directory or the specified directory.
- `cd <path>`
  Changes the current directory.

Examples:

```text
pwd
ls
cd docs
ls
cd /home/alice
```

### Directory Management

- `mkdir <path>`
  Creates a directory.

Examples:

```text
mkdir docs
mkdir docs/notes
mkdir /home/alice/shared
```

### File Management

- `create <remote_path> [group_name]`
  Creates a file. If `group_name` is provided, the file is created with that group association.
- `write <remote_path> <text>`
  Encrypts the text you type and writes it to the remote file.
- `read <remote_path>`
  Reads the remote file, decrypts it locally, and prints the plaintext to the CLI.
- `rm <remote_path>`
  Deletes a file.
- `mv <source_path> <destination_path>`
  Renames or moves a file or directory.
- `chmod <mode_bits> <remote_path>`
  Updates the Unix-style mode bits for a file.

Examples:

```text
create docs/a.txt
write docs/a.txt hello world
read docs/a.txt
mv docs/a.txt docs/a2.txt
chmod 0600 docs/a2.txt
rm docs/a2.txt
```

### Group Management

- `group-create <group_name>`
  Creates a group. The logged-in user becomes the owner.
- `group-add <group_name> <username>`
  Adds a user to the group.
- `group-rm <group_name> <username>`
  Removes a user from the group.
- `group-list [username]`
  Lists the groups for the current user, or for the given username.
- `group-key <group_name>`
  Fetches the current user's wrapped group key for that group.

Examples:

```text
group-create devs
group-add devs bob
group-list
group-key devs
group-rm devs bob
```

## Path Rules

- Relative paths are resolved from your current CLI directory.
- Absolute paths also work, such as `/home/alice/docs/a.txt`.
- The CLI shows plaintext logical paths, but the client encrypts path components before sending them to the server.

Example:

```text
pwd
/home/alice

create docs/demo.txt
```

The file is logically created at:

```text
/home/alice/docs/demo.txt
```

## Demo 1: Basic File-System Flow

Copy this into the CLI after logging in as `alice`:

```text
pwd
mkdir docs
create docs/a.txt
write docs/a.txt hello from alice
read docs/a.txt
mv docs/a.txt docs/a2.txt
ls docs
chmod 0600 docs/a2.txt
logout
```

What this demonstrates:

- directories
- file creation
- encrypted write
- decrypted read
- rename/move
- listing
- permission update

## Demo 2: Group Flow

### Alice Creates The Group

Copy this into the CLI after logging in as `alice`:

```text
group-create devs
group-list
logout
```

### Bob Registers And Logs In

From a fresh client session:

```text
register
bob
bobpass
login
bob
bobpass
group-list
logout
```

### Alice Adds Bob To The Group

From a fresh client session as `alice`:

```text
login
alice
alicepass
group-add devs bob
group-list
logout
```

### Bob Verifies Access

From a fresh client session as `bob`:

```text
login
bob
bobpass
group-list
group-key devs
logout
```

What this demonstrates:

- group creation
- group ownership
- member add/remove support
- group membership visibility
- wrapped group key retrieval

## Demo 3: Group-Scoped File Creation

As `alice`, after `devs` already exists:

```text
login
alice
alicepass
create /groups/devs/shared.txt
write /groups/devs/shared.txt shared hello from alice
read /groups/devs/shared.txt
logout
```

What this demonstrates:

- shared group directory
- file creation inside a group-owned namespace
- group-wrapped FEK support
- encrypted content write
- local decryption on read

As `bob`, after Alice has already added him to `devs`:

```text
login
bob
bobpass
group-list
group-key devs
read /groups/devs/shared.txt
logout
```

This shows that a group member can resolve and decrypt content from the shared
group directory.

## Demo 4: Corruption Detection

1. Log in as `alice` and create a file:

```text
mkdir docs
create docs/check.txt
write docs/check.txt integrity test
logout
```

2. In another terminal, corrupt one stored file in the server storage:

```bash
python3 - <<'PY'
from pathlib import Path

files = [p for p in Path("server/deploy/storage/sfs_storage").rglob("*") if p.is_file()]
if not files:
    raise SystemExit("no stored files found")

target = files[-1]
data = bytearray(target.read_bytes())
if not data:
    raise SystemExit("cannot corrupt empty file")

data[0] ^= 1
target.write_bytes(data)
print(target)
PY
```

3. Start a fresh client and log in again as `alice`:

```text
login
alice
alicepass
logout
```

Expected behavior:

- the client should warn immediately after login that corruption was detected

## Demo 5: Encrypted Names And Encrypted Contents At Rest

After creating some files, run these commands from the repo root:

```bash
find server/deploy/storage/sfs_storage -type f -o -type d
sqlite3 server/deploy/storage/sqlite_data/sfs.db "select cast(path as text), cast(name as text), object_type from file_metadatas;"
```

What to point out:

- the on-disk names are encrypted
- the metadata `path` and `name` values are encrypted
- the server never stores user-facing plaintext names on disk

Optional content check:

```bash
xxd "$(find server/deploy/storage/sfs_storage -type f | head -n 1)" | head
```

This should look like ciphertext, not readable plaintext.

## Recommended Full Demo Sequence

If you want a short but strong end-to-end demo, use this order:

1. `register` and `login` as `alice`
2. `mkdir`, `create`, `write`, `read`, `mv`, `chmod`
3. `group-create devs`
4. `register` and `login` as `bob`
5. `group-add devs bob` as `alice`
6. `group-list`, `group-key devs`, and `read /groups/devs/shared.txt` as `bob`
7. show encrypted names/content at rest from the shell
8. corrupt a stored file
9. log in as `alice` again and show the integrity warning

## Quick Reference

Simple private file demo:

```text
login
alice
alicepass
mkdir docs
create docs/a.txt
write docs/a.txt hello world
read docs/a.txt
logout
```

Simple group demo:

```text
login
alice
alicepass
group-create devs
group-add devs bob
create /groups/devs/shared.txt
write /groups/devs/shared.txt group secret
logout
```
