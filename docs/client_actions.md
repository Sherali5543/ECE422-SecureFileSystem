# Client Action Guide

This guide describes the current client/server contract for auth, file actions, and group actions.

## Auth Flow

The client no longer uses a hardcoded test token.

Current auth works like this:

1. `POST /auth/register`
2. `POST /auth/login` with `username` to fetch a challenge
3. `POST /auth/login` again with `username` and a signed challenge to receive a bearer token
4. `POST /auth/logout` to invalidate that token

All authenticated routes expect:

```http
Authorization: Bearer <session-token>
```

## Common Notes

- The server runs over HTTPS/TLS.
- The CLI uses logical plaintext paths like `/home/alice/docs/a.txt`.
- The client encrypts each path component before sending it to the server.
- The server stores encrypted `path` and `name` blobs and never needs plaintext names for normal file CRUD.
- If you call the API manually with `curl`, you must send the encrypted path form, not the logical plaintext path.
- JSON requests use `Content-Type: application/json`.
- Raw file uploads use `Content-Type: application/octet-stream`.

## Encrypted Path Contract

The client translates a logical path like:

```text
/home/alice/docs/a.txt
```

into an encrypted slash-delimited path like:

```text
/4b86.../c3e9.../adc8.../1a23...
```

Each component is encrypted and hex-encoded separately so the server can still traverse parent and child directories without learning the plaintext names.

The server responses for metadata and listings also contain encrypted `path` and `name` values. The CLI decrypts names before displaying them.

## Auth Routes

### Register

- Method: `POST`
- Path: `/auth/register`
- Content-Type: `application/json`

Request body:

```json
{
  "username": "alice",
  "public_encryption_key": "<hex>",
  "public_signing_key": "<hex>",
  "home_path": "<encrypted-path>",
  "home_name": "<encrypted-component>",
  "user_home_path": "<encrypted-path>",
  "user_home_name": "<encrypted-component>"
}
```

Notes:

- The client derives the public keys locally from the entered credentials.
- The client also sends encrypted home-directory metadata so registration can provision the user's home directory immediately.
- Registration does not auto-login.

Success response:

```json
{
  "message": "registered",
  "user_id": 1
}
```

### Login

Step 1 request:

```json
{
  "username": "alice"
}
```

Step 1 response:

```json
{
  "challenge": "<hex>"
}
```

Step 2 request:

```json
{
  "username": "alice",
  "signature": "<hex>"
}
```

Step 2 response:

```json
{
  "token": "<session-token>"
}
```

### Logout

- Method: `POST`
- Path: `/auth/logout`
- Header: `Authorization: Bearer <session-token>`

Success response:

```json
{
  "message": "logged out"
}
```

## File Routes

### Create File

- Method: `POST`
- Path: `/files`
- Content-Type: `application/json`

Request body:

```json
{
  "filepath": "<encrypted-path>",
  "group_name": "devs",
  "wrapped_fek_owner": "<hex>",
  "wrapped_fek_group": "<hex>",
  "wrapped_fek_other": "<hex>"
}
```

Notes:

- `wrapped_fek_owner` is required.
- `group_name`, `wrapped_fek_group`, and `wrapped_fek_other` are optional.
- If `group_name` is provided, the caller must already be a member of that group.

Success response:

```json
{
  "message": "file created",
  "filepath": "<encrypted-path>",
  "file_id": 12
}
```

### Create Directory

- Method: `POST`
- Path: `/directories`
- Content-Type: `application/json`

Request body:

```json
{
  "dirpath": "<encrypted-path>"
}
```

Success response:

```json
{
  "message": "directory created",
  "dirpath": "<encrypted-path>",
  "directory_id": 17
}
```

### List Directory

- Method: `GET`
- Path: `/files`
- Query: `filepath=<encrypted-directory-path>`

Success response:

```json
{
  "directory": "<encrypted-directory-path>",
  "entries": [
    {
      "path": "<encrypted-path>",
      "name": "<encrypted-component>",
      "object_type": "file",
      "owner_id": 1,
      "group_id": null,
      "mode_bits": 416,
      "created_at": 1774488154,
      "updated_at": 1774488154
    }
  ]
}
```

The CLI decrypts each returned `name` before printing it.

### Get Metadata

- Method: `GET`
- Path: `/files/meta`
- Query: `filepath=<encrypted-path>`

Success response:

```json
{
  "path": "<encrypted-path>",
  "name": "<encrypted-component>",
  "object_type": "file",
  "owner_id": 1,
  "group_id": null,
  "mode_bits": 416,
  "created_at": 1774488154,
  "updated_at": 1774488154
}
```

The CLI uses this route to resolve metadata and scope information without relying on plaintext server paths.

### Write File Contents

- Method: `PUT`
- Path: `/files/content`
- Query: `filepath=<encrypted-path>`
- Content-Type: `application/octet-stream`

The client encrypts file contents locally with the FEK before upload.

Success response:

```json
{
  "message": "file written"
}
```

### Read File Contents

- Method: `GET`
- Path: `/files/contents`
- Query: `filepath=<encrypted-path>`

Success response:

- Status: `200 OK`
- Body: encrypted file bytes
- Response headers:
  - `X-Wrapped-FEK: <hex-encoded wrapped FEK>`
  - `X-FEK-Scope: owner|group|other`

The client unwraps the FEK locally and decrypts the returned bytes before writing or displaying the plaintext.

### Delete File

- Method: `DELETE`
- Path: `/files`
- Query: `filepath=<encrypted-path>`

Success response:

```json
{
  "message": "file deleted"
}
```

### Move Or Rename

- Method: `POST`
- Path: `/files/move`
- Content-Type: `application/json`

Request body:

```json
{
  "source_filepath": "<encrypted-source-path>",
  "destination_filepath": "<encrypted-destination-path>"
}
```

Success response:

```json
{
  "message": "path moved",
  "from": "<encrypted-source-path>",
  "to": "<encrypted-destination-path>"
}
```

### Update Permissions

- Method: `PATCH`
- Path: `/files/permissions`
- Content-Type: `application/json`

Request body:

```json
{
  "filepath": "<encrypted-path>",
  "mode_bits": "0640",
  "wrapped_fek_owner": "<hex>",
  "wrapped_fek_group": "<hex>",
  "wrapped_fek_other": "<hex>"
}
```

Notes:

- `mode_bits` can be an octal-style string like `"0640"` or a numeric value.
- Wrapped FEKs are hex strings.
- Owner FEK must always exist.
- Group FEK must exist if group bits are enabled and the file has a group.
- Other FEK must exist if other bits are enabled.

## Group Routes

### Create Group

- Method: `POST`
- Path: `/groups`
- Content-Type: `application/json`

Request body:

```json
{
  "group_name": "devs",
  "wrapped_group_key": "<hex>"
}
```

Success response:

```json
{
  "message": "group created",
  "group_name": "devs",
  "group_id": 3,
  "owner_id": 1
}
```

### Add User To Group

- Method: `POST`
- Path: `/groups/members`
- Content-Type: `application/json`

Request body:

```json
{
  "group_name": "devs",
  "username": "bob",
  "wrapped_group_key": "<hex>"
}
```

Only the group owner may add members.

### Remove User From Group

- Method: `DELETE`
- Path: `/groups/members`
- Content-Type: `application/json`

Request body:

```json
{
  "group_name": "devs",
  "username": "bob"
}
```

Only the group owner may remove members.

### List User Groups

- Method: `GET`
- Path: `/groups`
- Optional query: `username=<username>`

If `username` is omitted, the server uses the user from the current token.

Success response:

```json
{
  "username": "bob",
  "groups": [
    {
      "group_id": 3,
      "group_name": "devs",
      "owner_id": 1,
      "is_owner": false
    }
  ]
}
```

### Get Wrapped Group Key

- Method: `GET`
- Path: `/groups/key`
- Query: `group_name=<group_name>`

Success response:

```json
{
  "group_id": 3,
  "group_name": "devs",
  "owner_id": 1,
  "wrapped_group_key": "<hex>"
}
```

### Get User Public Keys

- Method: `GET`
- Path: `/users/keys`
- Query: `username=<username>`

Success response:

```json
{
  "username": "bob",
  "public_encryption_key": "<hex>",
  "public_signing_key": "<hex>"
}
```

This route is used by the client to wrap a group key for another user before calling `POST /groups/members`.

## Suggested Client Wrapper Shape

- `register(username, password)`
- `login(username, password)`
- `logout()`
- `encrypt_logical_path(path)`
- `decrypt_entry_name(parent_path, encrypted_name)`
- `get_metadata(filepath)`
- `create_file(filepath, wrapped_fek_owner, group_name=None, wrapped_fek_group=None, wrapped_fek_other=None)`
- `create_directory(dirpath)`
- `list_directory(dirpath)`
- `write_file(filepath, bytes)`
- `read_file(filepath)`
- `delete_file(filepath)`
- `move_path(source, destination)`
- `update_permissions(filepath, mode_bits, wrapped_fek_owner=None, wrapped_fek_group=None, wrapped_fek_other=None)`
- `create_group(group_name, wrapped_group_key)`
- `get_group_key(group_name)`
- `get_user_keys(username)`
- `add_group_member(group_name, username, wrapped_group_key)`
- `remove_group_member(group_name, username)`
- `list_user_groups(username=None)`
