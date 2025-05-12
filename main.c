#define OPENSSL_BUILDING_OPENSSL      /* must come *before* any header */
#include "ssl/ssl_local.h"
#include <openssl/ssl.h>
#include "ct-verif.h"        /* CT-Verif macros (public_in, …) */

int tls_handshake_wrapper(unsigned char *ssl) {
    // SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    // SSL *ssl     = SSL_new(ctx);
    // BIO *bio     = BIO_new(BIO_s_mem());  /* dummy in/out */

    public_in(__SMACK_values(ssl, 64));
    // SSL_set_bio(ssl, bio, bio);
    return SSL_do_handshake(ssl);
}