#include <string.h>
#include <sodium.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include "encryption.h"

#define CHUNK_SIZE 1024

UserKeys* generate_read_keypair(char* username, char* password){
    UserKeys* kp = malloc(sizeof(UserKeys));

    size_t un_size = strlen(username);
    size_t pw_size = strlen(password);
    size_t seed_size = un_size + pw_size + 2;
    char* seed = calloc(crypto_box_SEEDBYTES, 1);

    if (seed == NULL || seed_size > crypto_box_SEEDBYTES) {
        free(seed);
        free(kp);
        return NULL;
    }

    memcpy(seed, username, un_size);
    seed[un_size] = '.';
    memcpy(seed + un_size + 1, password, pw_size);
    seed[seed_size - 1] = '\0'; 

    crypto_box_seed_keypair(kp->public_key, kp->secret_key, (const unsigned char*) seed);

    free(seed);

    return kp;
}

SignKeys* generate_signing_keypair(char* username, char* password){
    SignKeys* kp = malloc(sizeof(SignKeys));

    size_t un_size = strlen(username);
    size_t pw_size = strlen(password);
    size_t seed_size = un_size + pw_size + 2;
    char* seed = calloc(crypto_sign_SEEDBYTES, 1);

    if (seed == NULL || seed_size > crypto_sign_SEEDBYTES) {
        free(seed);
        free(kp);
        return NULL;
    }

    memcpy(seed, username, un_size);
    seed[un_size] = '.';
    memcpy(seed + un_size + 1, password, pw_size);
    seed[seed_size - 1] = '\0'; 

    crypto_sign_seed_keypair(kp->public_key, kp->secret_key, (const unsigned char *)seed);

    free(seed);

    return kp;
}


char* generate_file_key(){
    char* key = malloc(crypto_secretstream_xchacha20poly1305_KEYBYTES);

    crypto_secretstream_xchacha20poly1305_keygen((unsigned char *)key);

    return key;
}

char* generate_group_key(){
    char* key = malloc(crypto_secretbox_KEYBYTES);

    crypto_secretbox_keygen((unsigned char *)key);

    return key;
}


char* encrypt_wrapped_user_key(UserKeys* user_keys, char* main_key){
    char* wrapped_key = malloc(crypto_box_SEALBYTES + crypto_secretstream_xchacha20poly1305_KEYBYTES);

    if(crypto_box_seal((unsigned char *)wrapped_key, 
                        (const unsigned char *) main_key, crypto_secretstream_xchacha20poly1305_KEYBYTES, 
                        user_keys->public_key) != 0){
        return NULL;
    }

    return wrapped_key;
}

char* decrypt_wrapped_user_key(UserKeys* user_keys, char* encrypted_key){
    // ok so like this is probably illegal because file_keys and group_keys
    // are different keys. HOWEVER, they are both 32U, so it functionally works
    // ☺️
    char* unwrapped_key = malloc(crypto_secretstream_xchacha20poly1305_KEYBYTES);

    if(crypto_box_seal_open((unsigned char *) unwrapped_key, 
                                (const unsigned char *) encrypted_key, 
                                crypto_box_SEALBYTES + crypto_secretstream_xchacha20poly1305_KEYBYTES,
                                user_keys->public_key, user_keys->secret_key) != 0){
        return NULL;
    }

    return unwrapped_key;
}


char* encrypt_file_group_key(char* file_key, char* group_key){
    char* wrapped_key = malloc(crypto_secretbox_MACBYTES + crypto_secretstream_xchacha20poly1305_KEYBYTES);

    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    sodium_memzero(nonce, crypto_secretbox_NONCEBYTES);

    crypto_secretbox_easy((unsigned char *)wrapped_key, (const unsigned char *) file_key, crypto_secretstream_xchacha20poly1305_KEYBYTES, 
                            nonce, (const unsigned char *) group_key);

    return wrapped_key;
}


char* decrypt_file_group_key(char* group_key, char* encrypted_key){
    char* unwrapped_key = malloc(crypto_secretstream_xchacha20poly1305_KEYBYTES);

    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    sodium_memzero(nonce, crypto_secretbox_NONCEBYTES);

    if(crypto_secretbox_open_easy((unsigned char *)unwrapped_key, (const unsigned char *)
                                    encrypted_key, 
                                    crypto_secretbox_MACBYTES + crypto_secretstream_xchacha20poly1305_KEYBYTES, 
                                    nonce, (const unsigned char* )group_key) != 0){
        return NULL;
    }

    return unwrapped_key;
}

char* generate_file_hash(char* filepath){
    char* hash = malloc(crypto_generichash_BYTES);

    crypto_generichash_state state;
    crypto_generichash_init(&state, NULL, 0, crypto_generichash_BYTES);

    char buffer[CHUNK_SIZE];
    
    int fd = open(filepath, O_RDONLY);
    ssize_t amount_read;
    while(1){
        // read the original file
        amount_read = read(fd, buffer, sizeof(buffer));

        if(amount_read == 0){
            break;
        }

        crypto_generichash_update(&state, (const unsigned char *) buffer, (unsigned long long) amount_read);
    }

    crypto_generichash_final(&state, (unsigned char *)hash, crypto_generichash_BYTES);

    return hash;
}



char* generate_hash_signature(char* hash, SignKeys* sign_keys){
    char* signature = malloc(crypto_sign_BYTES + crypto_generichash_BYTES);

    crypto_sign((unsigned char*) signature, NULL, (unsigned char *)hash, crypto_generichash_BYTES,(sign_keys->secret_key));

    return signature;
}

char* generate_bytes_signature(const unsigned char* bytes, size_t len,
                               SignKeys* sign_keys) {
    unsigned long long signed_len = 0;
    char* signature = NULL;

    if (bytes == NULL || sign_keys == NULL) {
        return NULL;
    }

    signature = malloc(crypto_sign_BYTES + len);
    if (signature == NULL) {
        return NULL;
    }

    if (crypto_sign((unsigned char*)signature, &signed_len, bytes,
                    (unsigned long long)len, sign_keys->secret_key) != 0 ||
        signed_len != crypto_sign_BYTES + len) {
        free(signature);
        return NULL;
    }

    return signature;
}


char* encrypt_file(char* file_key, char* filepath){
    unsigned char inbuf[CHUNK_SIZE];
    unsigned char outbuf[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];

    char* temp_filename = strdup("/tmp/sfs_encrypt_XXXXXX");
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state state;

    int temp_fd = mkstemp(temp_filename);

    crypto_secretstream_xchacha20poly1305_init_push(&state, header, (const unsigned char *) file_key);

    write(temp_fd, header, crypto_secretstream_xchacha20poly1305_HEADERBYTES);

    ssize_t amount_read;
    unsigned long long out_len;
    int fd = open(filepath, O_RDONLY);
    unsigned char tag = 0;
    while(1){
        // read the original file
        amount_read = read(fd, (unsigned char*)inbuf, sizeof(inbuf));

        if(amount_read == 0){
            break;
        }

        // check if this is the final segment
        if ((unsigned long) amount_read < sizeof(inbuf)){
            tag = crypto_secretstream_xchacha20poly1305_TAG_FINAL;
        }

        // do the encryption for this segment
        if (crypto_secretstream_xchacha20poly1305_push(
            &state,
            outbuf,
            &out_len,
            inbuf,
            (long long unsigned int) amount_read,
            NULL,
            0,
            tag
        ) != 0){
        }


        // write the results to the temp file
        unsigned long long total_written = 0;
        while(total_written < out_len){
            ssize_t nwritten = write(temp_fd, outbuf + total_written, out_len - total_written);

            total_written += (unsigned long long) nwritten;
        }

        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
            break;
        }
    }

    close(temp_fd);
    close(fd);

    sodium_memzero(&state, sizeof state);
    sodium_memzero(inbuf, sizeof inbuf);
    sodium_memzero(outbuf, sizeof outbuf);

    return temp_filename;
}



char* decrypt_file(char* file_key, char* filepath){
    unsigned char inbuf[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char outbuf[CHUNK_SIZE];

    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];    
    
    int fd = open(filepath, O_RDONLY);

    read(fd, header, crypto_secretstream_xchacha20poly1305_HEADERBYTES);

    char* temp_filename = strdup("/tmp/sfs_decrypt_XXXXXX");
    crypto_secretstream_xchacha20poly1305_state state;

    int temp_fd = mkstemp(temp_filename);

    crypto_secretstream_xchacha20poly1305_init_pull(&state, (const unsigned char*) header, (const unsigned char *)file_key);

    ssize_t amount_read;
    unsigned long long out_len;
    unsigned char tag;
    while(1){
        // read the original file
        amount_read = read(fd, inbuf, sizeof(inbuf));

        if(amount_read == 0){
        }

        // do the encryption for this segment
        if (crypto_secretstream_xchacha20poly1305_pull(
            &state,
            outbuf,
            &out_len,
            &tag,
            inbuf,
            (unsigned long long) amount_read,
            NULL,
            0) != 0){
        }


        // write the results to the temp file
        unsigned long long total_written = 0;
        while(total_written < out_len){
            ssize_t nwritten = write(temp_fd, outbuf + total_written, out_len - total_written);

            total_written += (unsigned long long) nwritten;
        }

        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
            break;
        }
    }

    close(temp_fd);
    close(fd);

    sodium_memzero(&state, sizeof state);
    sodium_memzero(inbuf, sizeof inbuf);
    sodium_memzero(outbuf, sizeof outbuf);

    return temp_filename;
}

int derive_private_name_key(const UserKeys* user_keys,
                            unsigned char out_key[crypto_secretbox_KEYBYTES]) {
    if (user_keys == NULL || out_key == NULL) {
        return -1;
    }

    memcpy(out_key, user_keys->secret_key, crypto_secretbox_KEYBYTES);
    return 0;
}

char* encrypt_name_component_hex(const unsigned char* name_key,
                                 const char* component) {
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    unsigned char* packed = NULL;
    unsigned char* ciphertext = NULL;
    char* hex = NULL;
    size_t component_len = 0;
    size_t packed_len = 0;

    if (name_key == NULL || component == NULL || component[0] == '\0') {
        return NULL;
    }

    component_len = strlen(component);
    packed_len = crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES +
                 component_len;

    packed = malloc(packed_len);
    ciphertext = malloc(crypto_secretbox_MACBYTES + component_len);
    hex = malloc(packed_len * 2 + 1);
    if (packed == NULL || ciphertext == NULL || hex == NULL) {
        free(packed);
        free(ciphertext);
        free(hex);
        return NULL;
    }

    crypto_generichash(nonce, sizeof(nonce), (const unsigned char*)component,
                       (unsigned long long)component_len, name_key,
                       crypto_secretbox_KEYBYTES);
    crypto_secretbox_easy(ciphertext, (const unsigned char*)component,
                          (unsigned long long)component_len, nonce, name_key);

    memcpy(packed, nonce, crypto_secretbox_NONCEBYTES);
    memcpy(packed + crypto_secretbox_NONCEBYTES, ciphertext,
           crypto_secretbox_MACBYTES + component_len);
    sodium_bin2hex(hex, packed_len * 2 + 1, packed, packed_len);

    sodium_memzero(nonce, sizeof(nonce));
    sodium_memzero(ciphertext, crypto_secretbox_MACBYTES + component_len);
    sodium_memzero(packed, packed_len);
    free(ciphertext);
    free(packed);
    return hex;
}

char* decrypt_name_component_hex(const unsigned char* name_key,
                                 const char* component_hex) {
    unsigned char* packed = NULL;
    unsigned char* plaintext = NULL;
    char* out = NULL;
    const unsigned char* nonce = NULL;
    const unsigned char* ciphertext = NULL;
    size_t hex_len = 0;
    size_t packed_len = 0;
    size_t ciphertext_len = 0;

    if (name_key == NULL || component_hex == NULL || component_hex[0] == '\0') {
        return NULL;
    }

    hex_len = strlen(component_hex);
    if ((hex_len % 2) != 0) {
        return NULL;
    }

    packed_len = hex_len / 2;
    if (packed_len <= crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES) {
        return NULL;
    }

    packed = malloc(packed_len);
    if (packed == NULL) {
        return NULL;
    }
    if (sodium_hex2bin(packed, packed_len, component_hex, hex_len, NULL,
                       &packed_len, NULL) != 0) {
        free(packed);
        return NULL;
    }

    nonce = packed;
    ciphertext = packed + crypto_secretbox_NONCEBYTES;
    ciphertext_len = packed_len - crypto_secretbox_NONCEBYTES;
    plaintext = malloc(ciphertext_len - crypto_secretbox_MACBYTES + 1);
    if (plaintext == NULL) {
        sodium_memzero(packed, packed_len);
        free(packed);
        return NULL;
    }

    if (crypto_secretbox_open_easy(plaintext, ciphertext,
                                   (unsigned long long)ciphertext_len, nonce,
                                   name_key) != 0) {
        sodium_memzero(plaintext, ciphertext_len - crypto_secretbox_MACBYTES + 1);
        free(plaintext);
        sodium_memzero(packed, packed_len);
        free(packed);
        return NULL;
    }

    plaintext[ciphertext_len - crypto_secretbox_MACBYTES] = '\0';
    out = strdup((char*)plaintext);
    sodium_memzero(plaintext, ciphertext_len - crypto_secretbox_MACBYTES + 1);
    free(plaintext);
    sodium_memzero(packed, packed_len);
    free(packed);
    return out;
}


int test_encryption() {
    int ok = 0;

    char *username = "alice";
    char *password = "correcthorsebatterystaple";

    UserKeys *user_keys = NULL;
    SignKeys *sign_keys = NULL;

    char *file_key = NULL;
    char *group_key = NULL;

    char *wrapped_file_key = NULL;
    char *unwrapped_file_key = NULL;

    char *encrypted_group_file_key = NULL;
    char *decrypted_group_file_key = NULL;

    char *original_hash = NULL;
    char *signature = NULL;
    char *verified_hash = NULL;

    char *encrypted_file_path = NULL;
    char *decrypted_file_path = NULL;

    const char *test_plaintext_path = "/tmp/sfs_test_plain.txt";
    FILE *fp = NULL;

    printf("=== Starting encryption flow test ===\n");

    // Create deterministic user keypairs
    user_keys = generate_read_keypair(username, password);
    if (user_keys == NULL) {
        fprintf(stderr, "generate_read_keypair failed\n");
        goto cleanup;
    }

    sign_keys = generate_signing_keypair(username, password);
    if (sign_keys == NULL) {
        fprintf(stderr, "generate_signing_keypair failed\n");
        goto cleanup;
    }

    char hex[crypto_sign_SECRETKEYBYTES * 2 + 1];

    sodium_bin2hex(hex, sizeof hex,
                user_keys->public_key,
                crypto_box_PUBLICKEYBYTES);
    printf("USER PUBLIC: %s\n", hex);

    sodium_bin2hex(hex, sizeof hex,
                user_keys->secret_key,
                crypto_box_SECRETKEYBYTES);
    printf("USER SECRET: %s\n", hex);

    sodium_bin2hex(hex, sizeof hex,
                sign_keys->public_key,
                crypto_sign_PUBLICKEYBYTES);
    printf("SIGN PUBLIC: %s\n", hex);

    sodium_bin2hex(hex, sizeof hex,
                sign_keys->secret_key,
                crypto_sign_SECRETKEYBYTES);
    printf("SIGN SECRET: %s\n", hex);

    printf("[OK] generated user and signing keypairs\n");

    // Generate symmetric keys
    file_key = generate_file_key();
    if (file_key == NULL) {
        fprintf(stderr, "generate_file_key failed\n");
        goto cleanup;
    }

    group_key = generate_group_key();
    if (group_key == NULL) {
        fprintf(stderr, "generate_group_key failed\n");
        goto cleanup;
    }

    printf("[OK] generated file key and group key\n");

    // Wrap file key with user public/private flow
    wrapped_file_key = encrypt_wrapped_user_key(user_keys, file_key);
    if (wrapped_file_key == NULL) {
        fprintf(stderr, "encrypt_wrapped_user_key failed\n");
        goto cleanup;
    }

    unwrapped_file_key = decrypt_wrapped_user_key(user_keys, wrapped_file_key);
    if (unwrapped_file_key == NULL) {
        fprintf(stderr, "decrypt_wrapped_user_key failed\n");
        goto cleanup;
    }

    if (strcmp(file_key, unwrapped_file_key) != 0) {
        fprintf(stderr, "wrapped/unwrapped file key mismatch\n");
        goto cleanup;
    }

    printf("[OK] user-wrapped key round trip succeeded\n");

    // Wrap file key with group key
    encrypted_group_file_key = encrypt_file_group_key(file_key, group_key);
    if (encrypted_group_file_key == NULL) {
        fprintf(stderr, "encrypt_file_group_key failed\n");
        goto cleanup;
    }

    decrypted_group_file_key = decrypt_file_group_key(group_key, encrypted_group_file_key);
    if (decrypted_group_file_key == NULL) {
        fprintf(stderr, "decrypt_file_group_key failed\n");
        goto cleanup;
    }

    if (strcmp(file_key, decrypted_group_file_key) != 0) {
        fprintf(stderr, "group-wrapped file key mismatch\n");
        goto cleanup;
    }

    printf("[OK] group-wrapped key round trip succeeded\n");

    // Create a plaintext file
    fp = fopen(test_plaintext_path, "w");
    if (fp == NULL) {
        perror("fopen");
        goto cleanup;
    }

    fprintf(fp, "hello secure filesystem\n");
    fclose(fp);
    fp = NULL;

    printf("[OK] created plaintext file: %s\n", test_plaintext_path);

    // Hash and sign it
    original_hash = generate_file_hash((char *)test_plaintext_path);
    if (original_hash == NULL) {
        fprintf(stderr, "generate_file_hash failed\n");
        goto cleanup;
    }

    signature = generate_hash_signature((char *)test_plaintext_path, sign_keys);
    if (signature == NULL) {
        fprintf(stderr, "generate_hash_signature failed\n");
        goto cleanup;
    }

    verified_hash = decrypt_hash_signature(signature, (char *)sign_keys->public_key);
    if (verified_hash == NULL) {
        fprintf(stderr, "decrypt_hash_signature failed\n");
        goto cleanup;
    }

    if (strcmp(original_hash, verified_hash) != 0) {
        fprintf(stderr, "signature verification hash mismatch\n");
        goto cleanup;
    }

    printf("[OK] file hash signature verified\n");


    // Encrypt file
    encrypted_file_path = encrypt_file(file_key, (char *)test_plaintext_path);
    if (encrypted_file_path == NULL) {
        fprintf(stderr, "encrypt_file failed\n");
        goto cleanup;
    }

    printf("[OK] encrypted file -> %s\n", encrypted_file_path);

    // Decrypt file
    decrypted_file_path = decrypt_file(file_key, encrypted_file_path);
    if (decrypted_file_path == NULL) {
        fprintf(stderr, "decrypt_file failed\n");
        goto cleanup;
    }

    printf("[OK] decrypted file -> %s\n", decrypted_file_path);

    // Re-hash decrypted file and compare
    {
        char *decrypted_hash = generate_file_hash(decrypted_file_path);
        if (decrypted_hash == NULL) {
            fprintf(stderr, "generate_file_hash on decrypted file failed\n");
            goto cleanup;
        }

        if (strcmp(original_hash, decrypted_hash) != 0) {
            fprintf(stderr, "decrypted file hash mismatch\n");
            free(decrypted_hash);
            goto cleanup;
        }

        free(decrypted_hash);
    }

    printf("[OK] decrypted file content matches original hash\n");

    ok = 1;
    printf("=== encryption flow test PASSED ===\n");

cleanup:
    if (!ok) {
        fprintf(stderr, "=== encryption flow test FAILED ===\n");
    }

    if (fp != NULL) {
        fclose(fp);
    }

    if (encrypted_file_path != NULL) {
        unlink(encrypted_file_path);
    }

    if (decrypted_file_path != NULL) {
        unlink(decrypted_file_path);
    }

    unlink(test_plaintext_path);

    free(user_keys);
    free(sign_keys);

    free(file_key);
    free(group_key);

    free(wrapped_file_key);
    free(unwrapped_file_key);

    free(encrypted_group_file_key);
    free(decrypted_group_file_key);

    free(original_hash);
    free(signature);
    free(verified_hash);

    return ok ? 0 : -1;
}
