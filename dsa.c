#define DEBUG

#include <stdio.h>
#include <string.h>

#include <openssl/ossl_typ.h>
#include <openssl/err.h>
#include <openssl/dsa.h>
#include <openssl/md5.h>

int main(int argc, char **argv) {
	DSA *dsa = DSA_new();
	DSA_generate_parameters_ex(dsa, 512, NULL, 0, NULL, NULL, NULL);
	DSA_generate_key(dsa);

	/* Print dsa params to file */
	FILE *fd = fopen("dsa_param", "w");
	int res = DSA_print_fp(fd, dsa, 0);

	unsigned char *msg = "Normal non-fake message";
#ifdef DEBUG
	printf("Message - %s\n", msg);
	printf("Hex plaintext - ");
	for (int i = 0; i < strlen(msg); i++)
		printf("%02x", msg[i]);
	printf("\n");
#endif

	unsigned char *hash_sum = MD5(msg, strlen(msg), NULL);
#ifdef DEBUG
	printf("MD5 sum - ");
	for (int i = 0; i < strlen(hash_sum); i++)
		printf("%02x", hash_sum[i]);
	printf("\n");
#endif

	int sign_len;
	unsigned char *sign = malloc(DSA_size(dsa));

	DSA_sign(0, hash_sum, strlen(hash_sum), sign, &sign_len, dsa);
#ifdef DEBUG
	printf("Sign - ");
	for (int i = 0; i < sign_len; i++)
		printf("%02x", sign[i]);
	printf("\n");
#endif

	/* Prepare digital sign for sending (remove private key) */
	DSA *send_dsa = DSA_new();
	/* Transit pointers */
	BIGNUM *pub_key = BN_new();
	BIGNUM *p = BN_new();
	BIGNUM *q = BN_new();
	BIGNUM *g = BN_new();

	BIGNUM *send_pub_key = BN_new();
	BIGNUM *send_p = BN_new();
	BIGNUM *send_q = BN_new();
	BIGNUM *send_g = BN_new();

	DSA_get0_key(dsa, (const BIGNUM **) &pub_key, NULL);
	DSA_get0_pqg(dsa, (const BIGNUM **) &p, (const BIGNUM **) &q,
			(const BIGNUM **) &g);

	/* Make whole copy without private key */
	BN_copy(send_pub_key, pub_key);
	BN_copy(send_p, p);
	BN_copy(send_q, q);
	BN_copy(send_g, g);

	DSA_set0_key(send_dsa, send_pub_key, NULL);
	DSA_set0_pqg(send_dsa, send_p, send_q, send_g);

	/* Delete sign structure with private key */
	DSA_free(dsa);

	/* DSA for sending ready and now stored in send_dsa */
	/* Verify digital signature - sign+sign_len */
	unsigned char *received_message = "Normal non-fake message";
	unsigned char *rec_hash = MD5(received_message, strlen(received_message),
			NULL);
#ifdef DEBUG
	printf("Received message MD5 sum - ");
	for (int i = 0; i < strlen(rec_hash); i++)
		printf("%02x", rec_hash[i]);
	printf("\n");
#endif

	if ((DSA_verify(0, rec_hash, strlen(rec_hash), sign, sign_len, send_dsa))
			== 1)
		printf("Signature is valid. Result - OK\n");
	else
		printf("Message is invalid!\n");

	/* Fake message */
	unsigned char *received_fake_message = "Normal but fake message";
	unsigned char *rec_fake_hash = MD5(received_fake_message,
								strlen(received_fake_message), NULL);
#ifdef DEBUG
	printf("Received fake message MD5 sum - ");
	for (int i = 0; i < strlen(rec_fake_hash); i++)
		printf("%02x", rec_fake_hash[i]);
	printf("\n");
#endif

	if ((DSA_verify(0, rec_fake_hash, strlen(rec_fake_hash), sign, sign_len,
				send_dsa)) == 1)
		printf("Signature is valid. Result - OK\n");
	else
		printf("Message is invalid!\n");

	fclose(fd);
	DSA_free(send_dsa);
	free(sign);

	exit(0);
}
