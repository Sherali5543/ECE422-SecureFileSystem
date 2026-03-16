# Secure File System (SFS)

**Course:** ECE 422\
**Institution:** University of Alberta\
**Project Type:** Course Project

**Authors:**

-   Shaheer Khan
-   Andy Charlton
-   Abs Salim
-   Julian Jedrych

------------------------------------------------------------------------

## Overview

Secure File System (SFS) is a client-server system designed to securely
store and manage files on an untrusted server. The system provides
encrypted storage, user authentication, and permission-controlled file
access through a command-line interface.

Files are encrypted before being stored on the server, ensuring that
even if server storage is inspected directly, the contents remain
unreadable without proper cryptographic keys.

The project is implemented in **C** and uses modern cryptographic
primitives to provide:

-   Confidentiality
-   Integrity verification
-   Secure authentication
-   Controlled file access

------------------------------------------------------------------------

## Key Features

-   Client-server architecture
-   Encrypted file storage
-   Secure TLS communication
-   User authentication
-   Unix-like filesystem interface
-   Permission model (owner / group / other)
-   Database-backed metadata
-   Dockerized server deployment

------------------------------------------------------------------------

## Architecture

The system is composed of three primary components:

    Client (CLI)
         │
         │ TLS + REST API
         ▼
    Server
         │
         ├── MySQL Database (metadata)
         │
         └── Encrypted Storage (filesystem)

### Client

The client provides a CLI interface that allows users to interact with
the secure file system.

Example commands include:

    login
    ls
    cd
    mkdir
    create
    read
    write
    rm
    mv
    logout

The client handles:

-   user authentication
-   encryption/decryption
-   integrity verification
-   communication with the server

------------------------------------------------------------------------

### Server

The server is responsible for:

-   authenticating users
-   enforcing permissions
-   managing file metadata
-   storing encrypted file data
-   coordinating key management

The server **never stores plaintext file contents**.

------------------------------------------------------------------------

### Database

The MySQL database stores **metadata only**, including:

-   users
-   password hashes
-   group memberships
-   file permissions
-   encrypted filenames
-   wrapped file encryption keys
-   storage object mappings

Actual file data is stored separately on disk.

------------------------------------------------------------------------

## Cryptography

The system uses two cryptographic libraries.

### Libsodium

Used for most cryptographic operations:

-   AEGIS-256 authenticated encryption
-   Ed25519 digital signatures
-   X25519 key exchange
-   constant-time comparisons

### OpenSSL

Used exclusively for:

-   TLS communication between client and server

------------------------------------------------------------------------

## Encryption Model

The system uses a layered encryption design.

### Data in Transit

All client-server communication occurs over **TLS**.

### Data at Rest

Each file is encrypted using a unique **File Encryption Key (FEK)**.

The FEK is wrapped using:

-   the owner's public key
-   the file's group key
-   an optional "other" access key

This mirrors the Unix permission model.

------------------------------------------------------------------------

## Repository Structure

    secure-fs/
    │
    ├── client/               Client CLI implementation
    │
    ├── server/               Server implementation
    │   ├── src/
    │   ├── db/init/          Database schema
    │   ├── Dockerfile
    │   └── deploy/           Deployment configuration
    │       ├── docker-compose.yaml
    │       ├── secrets/      Runtime secrets (not committed)
    │       └── storage/      Encrypted file storage
    │
    ├── common/               Shared libraries
    │
    ├── docs/                 Project documentation
    │
    ├── build/                Build artifacts
    │
    └── CMakeLists.txt

------------------------------------------------------------------------

## Building the Project

The project uses **CMake**.

### Build locally

    mkdir build
    cd build
    cmake ..
    cmake --build .

Executables will be generated for:

-   `client`
-   `server`

------------------------------------------------------------------------

## Running the Server

The server is deployed using **Docker Compose**.

Navigate to the deployment directory:

    cd server/deploy

Copy environment template:

    cp .env.example .env

Create required secret files inside:

    server/deploy/secrets/

Required secrets include:

    db_password.txt
    mysql_root_password.txt
    server-cert.pem
    server-key.pem

Start the server:

    docker compose up --build

------------------------------------------------------------------------

## Running the Client

The client can be run locally after building:

    ./build/client/client --host <server-ip> --port 8443

Example:

    ./build/client/client --host 192.168.1.50 --port 8443

------------------------------------------------------------------------

## Security Considerations

The design assumes the **server storage may be untrusted**.

Security guarantees include:

-   encrypted file contents
-   encrypted filenames
-   integrity verification
-   secure authentication
-   permission enforcement

------------------------------------------------------------------------

## Future Work (Expandable)

Potential improvements:

-   GUI client
-   distributed storage backend
-   improved key rotation
-   performance benchmarking
-   additional security hardening

------------------------------------------------------------------------

## License

This project was developed for academic purposes as part of **ECE 422**
and is not intended for production deployment.

------------------------------------------------------------------------

## Acknowledgements

Developed as part of the **University of Alberta ECE 422 Secure Systems
course**.
