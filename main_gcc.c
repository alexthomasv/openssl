#define OPENSSL_BUILDING_OPENSSL      /* must come *before* any header */
#include "ssl/ssl_local.h"
#include <openssl/ssl.h>
#include "ct-verif.h"        /* CT-Verif macros (public_in, …) */

int main() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    SSL *ssl     = SSL_new(ctx);
    BIO *bio     = BIO_new(BIO_s_mem());  /* dummy in/out */
    printf("sizeof(SSL) = %ld\n", sizeof(SSL));
    SSL_do_handshake(ssl);

    // SSL_set_bio(ssl, bio, bio);
    return 0;
}