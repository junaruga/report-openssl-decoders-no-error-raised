#include <stdio.h>
#include <stdlib.h>

#include <openssl/decoder.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/provider.h>

#define BUF_SIZE 1024

static int print_provider(OSSL_PROVIDER *prov, void *unused)
{
    printf("  %s\n", OSSL_PROVIDER_get0_name(prov));
    return 1;
}

static EVP_PKEY *
ossl_pkey_read(BIO *bio, const char *input_type, int selection, char *pass)
{
    void *ppass = (void *)pass;
    OSSL_DECODER_CTX *dctx;
    EVP_PKEY *pkey = NULL;
    int pos = 0, pos2;

    dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, input_type, NULL, NULL,
                                         selection, NULL, NULL);
    if (!dctx)
        goto out;
    if (OSSL_DECODER_CTX_set_pem_password_cb(dctx, PEM_def_callback,
                                             ppass) != 1)
        goto out;
    while (1) {
        if (OSSL_DECODER_from_bio(dctx, bio) == 1)
            goto out;
        if (BIO_eof(bio))
            break;
        pos2 = BIO_tell(bio);
        if (pos2 < 0 || pos2 <= pos)
            break;
        /* ossl_clear_error(); */
        pos = pos2;
    }
  out:
    BIO_reset(bio);
    OSSL_DECODER_CTX_free(dctx);
    return pkey;
}

EVP_PKEY *
ossl_pkey_read_generic(BIO *bio, char *pass)
{
    EVP_PKEY *pkey = NULL;
    const char *input_types[] = {"DER", "PEM"};
    int input_type_num = (int)(sizeof(input_types) / sizeof(char *));
    int selections[] = {
        EVP_PKEY_KEYPAIR,
        EVP_PKEY_KEY_PARAMETERS,
        EVP_PKEY_PUBLIC_KEY
    };
    int selection_num = (int)(sizeof(selections) / sizeof(int));
    int i, j;

    for (i = 0; i < input_type_num; i++) {
        for (j = 0; j < selection_num; j++) {
            pkey = ossl_pkey_read(bio, input_types[i], selections[j], pass);
            if (pkey) {
                goto out;
            }
        }
    }
  out:
    return pkey;
}

int main(int argc, char *argv[])
{
    int status = EXIT_SUCCESS;
    char pkey_file_path[BUF_SIZE];
    char pass[BUF_SIZE] = "";
    int fips_enabled = 0;
    FILE *fp = NULL;
    static char data[BUF_SIZE * BUF_SIZE];
    size_t data_size;
    BIO *bio = NULL;
    EVP_PKEY *pkey = NULL;

    if (argc < 2) {
        status = EXIT_FAILURE;
        fprintf(stderr, "Usage: %s pkey_file [pass]\n", argv[0]);
        goto end;
    }
    memset(pkey_file_path, 0x00, sizeof(pkey_file_path));
    strncpy(pkey_file_path, argv[1], strlen(argv[1]));
    printf("pkey_file_path: %s\n", pkey_file_path);
    if (argc >= 3) {
        memset(pass, 0x00, sizeof(pass));
        strncpy(pass, argv[2], strlen(argv[2]));
    }
    printf("pass: %s\n", pass);

    /* Print FIPS information. */
    printf("Loaded providers:\n");
    OSSL_PROVIDER_do_all(NULL, &print_provider, NULL);
    fips_enabled = EVP_default_properties_is_fips_enabled(NULL);
    printf("FIPS enabled: %s\n", (fips_enabled) ? "yes" : "no");

    if ((fp = fopen(argv[1], "r")) == NULL) {
        status = EXIT_FAILURE;
        fprintf(stderr, "[DEBUG] Failed to open the pkey file.\n");
        goto end;
    }

    memset(data, 0x00, sizeof(data));
    memset(&data_size, 0x00, sizeof(data_size));
    if ((data_size = fread(data, 1, sizeof(data), fp)) == 0) {
        status = EXIT_FAILURE;
        fprintf(stderr, "[DEBUG] Failed to read the pkey file.\n");
        goto end;
    }
    fclose(fp);
    fp = NULL;
    data[data_size] = '\0';

    bio = BIO_new_mem_buf(data, strlen(data));
    if (!bio) {
        status = EXIT_FAILURE;
        fprintf(stderr, "[DEBUG] BIO_new_mem_buf() failed.\n");
        goto end;
    }

    ERR_clear_error();
    pkey = ossl_pkey_read_generic(bio, pass);
    if (!pkey) {
        status = EXIT_FAILURE;
        printf("Couldn't get the pkey.\n");
        fprintf(stderr, "[DEBUG] errors start.\n");
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "[DEBUG] errors end.\n");
        goto end;
    }
    printf("Got a pkey! %p\n", (void *)pkey);
    printf("It's held by the provider %s\n",
           OSSL_PROVIDER_get0_name(EVP_PKEY_get0_provider(pkey)));
end:
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    if (bio) {
        BIO_free(bio);
    }
    if (fp) {
        fclose(fp);
    }
    return status;
}
