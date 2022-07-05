/*
 * Demo on how to use /dev/crypto device for ciphering.
 *
 * Placed under public domain.
 *
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <crypto/cryptodev.h>
#include "sha.h"

#include <assert.h>
#define	KEY_SIZE	16

//#define CRIOGET         _IOWR('c', 101, uint32_t)
//#define CIOCGSESSION    _IOWR('c', 102, struct session_op)
//#define CIOCFSESSION    _IOW('c', 103, __u32)
//#define CIOCCRYPT       _IOWR('c', 104, struct crypt_op)
//#define CIOCKEY         _IOWR('c', 105, struct crypt_kop)
//#define CIOCASYMFEAT    _IOR('c', 106, __u32)
//#define CIOCGSESSINFO   _IOWR('c', 107, struct session_info_op)


int sha_ctx_init(struct cryptodev_ctx* ctx, int cfd, const uint8_t *key, unsigned int key_size)
{
#ifdef CIOCGSESSION2
    struct crypt_find_op fop;
#elif defined(CIOCGSESSINFO)
    struct session_info_op siop;
#endif

	memset(ctx, 0, sizeof(*ctx));
	ctx->cfd = cfd;

	if (key == NULL)
		ctx->sess.mac = CRYPTO_SHA1;
	else 
	{		
		//struct session_op {
		//       uint32_t	cipher;	   /* e.g. CRYPTO_AES_CBC */
		//       uint32_t	mac;	   /* e.g. CRYPTO_SHA2_256_HMAC	*/
		//       uint32_t	keylen;	   /* cipher key */
		//       const void *key;
		//       int mackeylen;	   /* mac key */
		//       const void *mackey;
		//       uint32_t	ses;	   /* returns: ses # */
		//};

		//ctx->sess.cipher = CRYPTO_AES_CBC;
		//ctx->sess.keylen = key_size;
		//ctx->sess.key = (void*)key;

		ctx->sess.mac = CRYPTO_SHA2_256_HMAC;
		ctx->sess.mackeylen = key_size;
		ctx->sess.mackey = (void*)key;
	}

#ifdef CIOCGSESSION2
	if (ioctl(ctx->cfd, CIOCGSESSION2, &ctx->sess)) {
		perror("ioctl(CIOCGSESSION2) 1");
		return -1;
	}
#else
	if (ioctl(ctx->cfd, CIOCGSESSION, &ctx->sess)) {
		perror("ioctl(CIOCGSESSION) 1");
		return -1;
	}
#endif

#ifdef CIOCGSESSION2
	fop.crid = ctx->sess.crid;
	if (ioctl(ctx->cfd, CIOCFINDDEV , &fop)) {
		perror("ioctl(CIOCFINDDEV)");
		return -1;
	}

	printf("CIOCGSESSION2 Driver Name: %.*s\n", (int)strlen(fop.name), fop.name);

#elif defined(CIOCGSESSINFO)
	siop.ses = ctx->sess.ses;
	if (ioctl(ctx->cfd, CIOCGSESSINFO, &siop)) {
		perror("ioctl(CIOCGSESSINFO)");
		return -1;
	}
	
	/*printf("Alignmask is %x\n", (unsigned int)siop.alignmask);*/
	ctx->alignmask = siop.alignmask;
#endif

	return 0;
}

void sha_ctx_deinit(struct cryptodev_ctx* ctx) 
{
	if (ioctl(ctx->cfd, CIOCFSESSION, &ctx->sess.ses)) {
		perror("ioctl(CIOCFSESSION)");
	}
}

int
sha_hash(struct cryptodev_ctx* ctx, const void* text, size_t size, void* digest)
{
	struct crypt_op cryp;
	void* p;
	
	/* check text and ciphertext alignment */
	if (ctx->alignmask) {
		p = (void*)(((unsigned long)text + ctx->alignmask) & ~ctx->alignmask);
		if (text != p) {
			fprintf(stderr, "text is not aligned\n");
			return -1;
		}
	}

	memset(&cryp, 0, sizeof(cryp));

	/* Encrypt data.in to data.encrypted */
	cryp.ses = ctx->sess.ses;
	cryp.len = size;
	cryp.src = (void*)text;
	cryp.mac = digest;
	if (ioctl(ctx->cfd, CIOCCRYPT, &cryp)) {
		perror("ioctl(CIOCCRYPT)");
		return -1;
	}

	return 0;
}

int
main()
{
	char plaintext1_raw[AES_BLOCK_SIZE + 63], *plaintext1;
	char ciphertext1[AES_BLOCK_SIZE] = { 0xdf, 0x55, 0x6a, 0x33, 0x43, 0x8d, 0xb8, 0x7b, 0xc4, 0x1b, 0x17, 0x52, 0xc5, 0x5e, 0x5e, 0x49 };
	char iv1[AES_BLOCK_SIZE];
	uint8_t key1[KEY_SIZE] = { 0xff, 0xff, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	char plaintext2_data[AES_BLOCK_SIZE] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc0, 0x00 };
	char plaintext2_raw[AES_BLOCK_SIZE + 63], *plaintext2;
	char ciphertext2[AES_BLOCK_SIZE] = { 0xb7, 0x97, 0x2b, 0x39, 0x41, 0xc4, 0x4b, 0x90, 0xaf, 0xa7, 0xb2, 0x64, 0xbf, 0xba, 0x73, 0x87 };
	char iv2[AES_BLOCK_SIZE];
	uint8_t key2[KEY_SIZE];

	//int fd = -1;
	int cfd = -1, i;
	struct cryptodev_ctx ctx = {0};
	uint8_t digest[20];
	char text[] = "The quick brown fox jumps over the lazy dog";
	uint8_t expected[] = "\x2f\xd4\xe1\xc6\x7a\x2d\x28\xfc\xed\x84\x9e\xe1\xbb\x76\xe7\x39\x1b\x93\xeb\x12";

	uint8_t * secretKey = (uint8_t*)"IamASecretKey";
	unsigned int secretKeyLen = 13;
	
	/* Open the crypto device */
	cfd = open("/dev/crypto", O_RDWR, 0);
	if (cfd < 0) {
		perror("open(/dev/crypto)");
		return 1;
	}

	/* Clone file descriptor */
	//if (ioctl(fd, CRIOGET, &cfd)) {
	//	perror("ioctl(CRIOGET)");
	//	return 1;
	//}

	/* Set close-on-exec (not really neede here) */
	if (fcntl(cfd, F_SETFD, 1) == -1) {
		perror("fcntl(F_SETFD)");
		return 1;
	}

	sha_ctx_init(&ctx, cfd, key1, sizeof(key1));
	
	sha_hash(&ctx, text, strlen(text), digest);
	
	sha_ctx_deinit(&ctx);

	printf("digest: ");
	for (i = 0; i < 20; i++) {
		printf("%02x:", digest[i]);
	}
	printf("\n");
	
	if (memcmp(digest, expected, 20) != 0) {
		fprintf(stderr, "SHA1 hashing failed\n");
		return 1;
	}

	/* Close cloned descriptor */
	if (close(cfd)) {
		perror("close(cfd)");
		return 1;
	}

	/* Close the original descriptor */
	//if (close(fd)) {
	//	perror("close(fd)");
	//	return 1;
	//}
	return 0;
}

