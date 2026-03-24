#include <assert.h>
#include <err.h>
#include <sys/socket.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

__attribute__((noreturn)) static void tls_error(SSL_CTX* ctx, BIO* bio,
                                                SSL* ssl, const char* msg) {
  assert(!(ssl != NULL && bio != NULL));
  if (ssl != NULL) {
    SSL_shutdown(ssl);
    SSL_free(ssl);
  } else if (bio != NULL)
    BIO_free_all(bio);
  if (ctx != NULL) SSL_CTX_free(ctx);

  ERR_print_errors_fp(stderr);
  errx(EXIT_FAILURE, "%s", msg);
}

static void tls_warn(SSL* ssl, BIO* bio, const char* msg) {
  assert(!(ssl != NULL && bio != NULL));
  ERR_print_errors_fp(stderr);
  warnx("%s", msg);
  // BIO ownership passed to SSL so sanity check
  if (ssl != NULL)
    SSL_free(ssl);
  else if (bio != NULL)
    BIO_free_all(bio);
}

SSL_CTX* tls_server_config(const char* cert, const char* key) {
  if (!cert || !key)
    errx(EXIT_FAILURE, "SERVER_CERT and SERVER_KEY must be set");

  SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
  if (ctx == NULL) {
    tls_error(ctx, NULL, NULL, "Failed to create server SSL_CTX");
  }
  // Limit accepted versions
  if (!SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION)) {
    tls_error(ctx, NULL, NULL,
              "Failed to set the minimum TLS protocol version");
  }
  uint64_t opts = 0;
  // Since using http which has explicit message framing this is fine
  // opts |= SSL_OP_IGNORE_UNEXPECTED_EOF;
  opts |= SSL_OP_NO_RENEGOTIATION;  // Don't care about DoS attacks for project
  opts |= SSL_OP_CIPHER_SERVER_PREFERENCE;
  SSL_CTX_set_options(ctx, opts);

  if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0)
    tls_error(ctx, NULL, NULL, "Failed to load server certificate file");
  if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0)
    tls_error(ctx, NULL, NULL, "Failed to load server private key file");
  if (SSL_CTX_check_private_key(ctx) != 1)
    tls_error(ctx, NULL, NULL, "Key/cert mismatch");

  // We are not using mTLS so not verifying client
  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

  return ctx;
}

BIO* tls_server_init(SSL_CTX* ctx, const char* port) {
  BIO* acceptor_bio = BIO_new_accept(port);
  if (acceptor_bio == NULL) {
    tls_error(ctx, NULL, NULL, "Error creating acceptor bio");
  }
  BIO_set_bind_mode(acceptor_bio, BIO_BIND_REUSEADDR);
  // First accept initalizes
  if (BIO_do_accept(acceptor_bio) <= 0) {
    tls_error(ctx, NULL, NULL, "Error setting up acceptor socket");
  }

  return acceptor_bio;
}

SSL* tls_server_accept(SSL_CTX* ctx, BIO* abio) {
  ERR_clear_error();
  if (BIO_do_accept(abio) < 1) return NULL;
  BIO* client_bio = BIO_pop(abio);
  if (client_bio == NULL) {
    warnx("Failed to obtain client BIO");
    return NULL;
  }
  fprintf(stderr, "New client connection accepted\n");

  SSL* ssl = SSL_new(ctx);
  if (ssl == NULL) {
    tls_warn(NULL, client_bio, "Error creating SSL handle for new connection");
    return NULL;
  }
  SSL_set_bio(ssl, client_bio, client_bio);

  // --- ATTEMPT HANDSHAKE ---
  if (SSL_accept(ssl) <= 0) {
    tls_warn(ssl, NULL, "Error performing SSL handshake with client");
    return NULL;
  }

  return ssl;
}

SSL_CTX* tls_client_config(const char* ca_cert) {
  SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
  if (ctx == NULL) tls_error(NULL, NULL, NULL, "Failed to create CTX");

  if (!SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION)) {
    tls_error(ctx, NULL, NULL, "Failed to set min TLS version");
  }

  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

  if (SSL_CTX_load_verify_locations(ctx, ca_cert, NULL) != 1)
    tls_error(ctx, NULL, NULL, "Failed to load CA cert");

  return ctx;
}

SSL* tls_client_connect(SSL_CTX* ctx, const char* server_addr,
                        const char* server_port) {
  BIO* cbio = BIO_new_connect(server_addr);
  if (cbio == NULL)
    tls_error(ctx, NULL, NULL, "Failed to create client BIO");
  BIO_set_conn_port(cbio, server_port);
  if (BIO_do_connect(cbio) <= 0)
    tls_error(ctx, cbio, NULL, "Failed to connect to server");

  SSL* ssl = SSL_new(ctx);
  if (ssl == NULL)
    tls_error(ctx, cbio, NULL, "Failed to create SSL object");

  // Pass BIO into SSL
  SSL_set_bio(ssl, cbio, cbio);
  if (SSL_set_tlsext_host_name(ssl, server_addr) != 1)
    tls_error(ctx, NULL, ssl, "Failed to set SNI");
  if (SSL_set1_host(ssl, server_addr) != 1)
    tls_error(ctx, NULL, ssl, "Failed to set verify host");

  // Handshake
  if (SSL_connect(ssl) < 1) {
    // Can get additional info on failure
    if (SSL_get_verify_result(ssl) != X509_V_OK)
      printf("Verify error: %s\n",
             X509_verify_cert_error_string(SSL_get_verify_result(ssl)));
    tls_error(ctx, NULL, ssl, "TLS handshake failed");
  }
  printf("Connected with %s encryption\n", SSL_get_cipher(ssl));

  return ssl;
}

ssize_t tls_read(SSL* ssl, void* buf, size_t len) {
  size_t nread = 0;
  int ok = SSL_read_ex(ssl, buf, len, &nread);
  if (ok == 1) {
    return (ssize_t)nread;
  }

  int err = SSL_get_error(ssl, ok);
  if (err == SSL_ERROR_ZERO_RETURN) return 0;  // clean TLS shutdown / EOF
  tls_warn(NULL, NULL, "SSL_read_ex failed");
  return -1;
}

ssize_t tls_write(SSL* ssl, void* buf, size_t write_bytes) {
  size_t nwritten = 0;
  if (SSL_write_ex(ssl, buf, write_bytes, &nwritten) <= 0 ||
      nwritten != write_bytes) {
    tls_warn(NULL, NULL, "Error echoing client input");
    return -1;
  }

  return (ssize_t)nwritten;
}

void tls_cleanup(SSL_CTX* ctx, BIO* abio) {
  if(abio != NULL) BIO_free_all(abio);
  if(ctx != NULL) SSL_CTX_free(ctx);
}
