# Client Action Guide

This document describes how the client should call the server endpoints that are currently implemented for file actions and group actions.

## Current Auth Assumption

Right now the server uses a hardcoded test session in [server_context.c](/Users/andy/Desktop/ece422/ECE422-SecureFileSystem/server/src/server_context.c). Until real login is implemented, the client should send:

```http
Authorization: Bearer test-token-alice-123
```

All of the routes below require that header.

## Common Notes

- The server is expected to run over HTTPS/TLS.
- Logical file paths should be absolute paths like `/home/alice/docs/a.txt`.
- The current handlers do not URL-decode query strings, so the client should send plain paths without extra escaping when possible.
- For JSON requests, use `Content-Type: application/json`.
- For raw file content uploads, use `Content-Type: application/octet-stream`.

## File Actions

### Create File

Create an empty file entry in metadata and create the backing file on disk.

- Method: `POST`
- Path: `/files`
- Content-Type: `application/json`

Request body:

```json
{
  "filepath": "/home/alice/docs/a.txt"
}
```

Success response:

- Status: `201 Created`
- Body:

```json
{
  "message": "file created",
  "filepath": "/home/alice/docs/a.txt",
  "file_id": 12
}
```

Common error cases:

- `400 Bad Request` for missing or invalid `filepath`
- `401 Unauthorized` for missing or bad token
- `403 Forbidden` if the user cannot create in the parent directory
- `404 Not Found` if the parent directory is missing
- `409 Conflict` if the file already exists

Example:

```bash
curl -k -X POST https://localhost:8443/files \
  -H "Authorization: Bearer test-token-alice-123" \
  -H "Content-Type: application/json" \
  -d '{"filepath":"/home/alice/docs/a.txt"}'
```

### Write File Contents

Write raw bytes into an existing file.

- Method: `PUT`
- Path: `/files/content`
- Query: `filepath=/absolute/path`
- Content-Type: `application/octet-stream`

Example request:

```bash
curl -k -X PUT "https://localhost:8443/files/content?filepath=/home/alice/docs/a.txt" \
  -H "Authorization: Bearer test-token-alice-123" \
  -H "Content-Type: application/octet-stream" \
  --data-binary 'hello world'
```

Success response:

- Status: `200 OK`
- Body:

```json
{
  "message": "file written"
}
```

Common error cases:

- `400 Bad Request` for missing or invalid `filepath`
- `401 Unauthorized` for missing or bad token
- `403 Forbidden` if the user does not have write permission
- `404 Not Found` if the file metadata does not exist

### Read File Contents

Read the raw bytes for an existing file.

- Method: `GET`
- Path: `/files/contents`
- Query: `filepath=/absolute/path`

Example request:

```bash
curl -k "https://localhost:8443/files/contents?filepath=/home/alice/docs/a.txt" \
  -H "Authorization: Bearer test-token-alice-123"
```

Success response:

- Status: `200 OK`
- Body: raw file bytes

Common error cases:

- `400 Bad Request` for missing or invalid `filepath`
- `401 Unauthorized` for missing or bad token
- `403 Forbidden` if the user does not have read permission
- `404 Not Found` if the file metadata or backing file does not exist

### Delete File

Delete the file metadata entry and remove the backing file from storage.

- Method: `DELETE`
- Path: `/files`
- Query: `filepath=/absolute/path`

Example request:

```bash
curl -k -X DELETE "https://localhost:8443/files?filepath=/home/alice/docs/a.txt" \
  -H "Authorization: Bearer test-token-alice-123"
```

Success response:

- Status: `200 OK`
- Body:

```json
{
  "message": "file deleted"
}
```

Common error cases:

- `400 Bad Request` for missing or invalid `filepath`, or if the target is not a file
- `401 Unauthorized` for missing or bad token
- `403 Forbidden` if the user does not have delete permission
- `404 Not Found` if the file does not exist

### Create Directory

Create a directory entry in metadata and create the backing directory on disk.

- Method: `POST`
- Path: `/directories`
- Content-Type: `application/json`

Request body:

```json
{
  "dirpath": "/home/alice/docs/projects"
}
```

The handler also accepts `filepath` instead of `dirpath`, but `dirpath` is clearer for the client.

Success response:

- Status: `201 Created`
- Body:

```json
{
  "message": "directory created",
  "dirpath": "/home/alice/docs/projects",
  "directory_id": 17
}
```

Common error cases:

- `400 Bad Request` for missing or invalid `dirpath`
- `401 Unauthorized` for missing or bad token
- `403 Forbidden` if the user cannot create inside the parent directory
- `404 Not Found` if the parent directory does not exist
- `409 Conflict` if the destination path already exists

Example:

```bash
curl -k -X POST https://localhost:8443/directories \
  -H "Authorization: Bearer test-token-alice-123" \
  -H "Content-Type: application/json" \
  -d '{"dirpath":"/home/alice/docs/projects"}'
```

### List Directory Contents

List the direct children of a directory.

- Method: `GET`
- Path: `/files`
- Query: `filepath=/absolute/directory/path`

Example request:

```bash
curl -k "https://localhost:8443/files?filepath=/home/alice/docs" \
  -H "Authorization: Bearer test-token-alice-123"
```

Success response:

- Status: `200 OK`
- Body:

```json
{
  "directory": "/home/alice/docs",
  "entries": [
    {
      "path": "/home/alice/docs/a.txt",
      "name": "a.txt",
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

Common error cases:

- `400 Bad Request` for missing or invalid `filepath`
- `401 Unauthorized` for missing or bad token
- `403 Forbidden` if the user does not have directory read access
- `404 Not Found` if the directory does not exist

### Move Or Rename A Path

Move or rename a file or directory.

- Method: `POST`
- Path: `/files/move`
- Content-Type: `application/json`

Request body:

```json
{
  "source_filepath": "/home/alice/docs/a.txt",
  "destination_filepath": "/home/alice/docs/archive/a.txt"
}
```

Success response:

- Status: `200 OK`
- Body:

```json
{
  "message": "path moved",
  "from": "/home/alice/docs/a.txt",
  "to": "/home/alice/docs/archive/a.txt"
}
```

Common error cases:

- `400 Bad Request` for an invalid move request or moving a directory into itself
- `401 Unauthorized` for missing or bad token
- `403 Forbidden` if the user cannot move the source or cannot create in the destination parent
- `404 Not Found` if the source or destination parent does not exist
- `409 Conflict` if the destination path already exists

Example:

```bash
curl -k -X POST https://localhost:8443/files/move \
  -H "Authorization: Bearer test-token-alice-123" \
  -H "Content-Type: application/json" \
  -d '{"source_filepath":"/home/alice/docs/a.txt","destination_filepath":"/home/alice/docs/archive/a.txt"}'
```

### Update Permissions

Update the stored Unix-style mode bits for a file or directory.

- Method: `PATCH`
- Path: `/files/permissions`
- Content-Type: `application/json`

Request body:

```json
{
  "filepath": "/home/alice/docs/a.txt",
  "mode_bits": "0644"
}
```

`mode_bits` can be sent as an octal-style string like `"0644"` or as a numeric value like `420`.

Success response:

- Status: `200 OK`
- Body:

```json
{
  "message": "permissions updated",
  "filepath": "/home/alice/docs/a.txt",
  "mode_bits": 420
}
```

Common error cases:

- `400 Bad Request` for missing or invalid `filepath` or `mode_bits`
- `401 Unauthorized` for missing or bad token
- `403 Forbidden` if the caller is not the owner
- `404 Not Found` if the path does not exist

## Group Actions

### Create Group

Create a new group name in the database.

- Method: `POST`
- Path: `/groups`
- Content-Type: `application/json`

Request body:

```json
{
  "group_name": "devs"
}
```

Success response:

- Status: `201 Created`
- Body:

```json
{
  "message": "group created",
  "group_name": "devs",
  "group_id": 3
}
```

Common error cases:

- `400 Bad Request` for invalid `group_name`
- `401 Unauthorized` for missing or bad token
- `409 Conflict` if the group already exists

Example:

```bash
curl -k -X POST https://localhost:8443/groups \
  -H "Authorization: Bearer test-token-alice-123" \
  -H "Content-Type: application/json" \
  -d '{"group_name":"devs"}'
```

### Add User To Group

Add a user to an existing group and store that user’s wrapped group key.

- Method: `POST`
- Path: `/groups/members`
- Content-Type: `application/json`

Request body:

```json
{
  "group_name": "devs",
  "username": "bob",
  "wrapped_group_key": "demo-key"
}
```

Success response:

- Status: `200 OK`
- Body:

```json
{
  "message": "user added to group"
}
```

Common error cases:

- `400 Bad Request` for invalid JSON fields
- `401 Unauthorized` for missing or bad token
- `404 Not Found` if the group or user does not exist
- `409 Conflict` if the user is already in the group

Example:

```bash
curl -k -X POST https://localhost:8443/groups/members \
  -H "Authorization: Bearer test-token-alice-123" \
  -H "Content-Type: application/json" \
  -d '{"group_name":"devs","username":"bob","wrapped_group_key":"demo-key"}'
```

### Remove User From Group

Remove a user from an existing group.

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

Success response:

- Status: `200 OK`
- Body:

```json
{
  "message": "user removed from group"
}
```

Common error cases:

- `400 Bad Request` for invalid JSON fields
- `401 Unauthorized` for missing or bad token
- `404 Not Found` if the group or user does not exist, or if the user is not in the group

Example:

```bash
curl -k -X DELETE https://localhost:8443/groups/members \
  -H "Authorization: Bearer test-token-alice-123" \
  -H "Content-Type: application/json" \
  -d '{"group_name":"devs","username":"bob"}'
```

### List A User's Groups

Return the groups for a given user.

- Method: `GET`
- Path: `/groups`
- Optional query: `username=<username>`

If `username` is omitted, the server uses the username from the current session token.

Example request:

```bash
curl -k "https://localhost:8443/groups?username=bob" \
  -H "Authorization: Bearer test-token-alice-123"
```

Success response:

- Status: `200 OK`
- Body:

```json
{
  "username": "bob",
  "groups": [
    {
      "group_id": 3,
      "group_name": "devs"
    }
  ]
}
```

Common error cases:

- `400 Bad Request` for an invalid `username` query
- `401 Unauthorized` for missing or bad token
- `404 Not Found` if the target user does not exist

## Not Implemented Yet

These routes are still placeholders or not wired up yet:

- `POST /auth/login`
- `POST /auth/register`
- `POST /auth/logout`

## Suggested Client Wrapper Shape

If you want a thin client wrapper layer, these are the core actions it should expose:

- `create_file(filepath)`
- `write_file(filepath, bytes)`
- `read_file(filepath)`
- `delete_file(filepath)`
- `create_group(group_name)`
- `add_group_member(group_name, username, wrapped_group_key)`
- `remove_group_member(group_name, username)`
- `list_user_groups(username=None)`

That will line up closely with the current server implementation and make it easier to swap in real auth later.
