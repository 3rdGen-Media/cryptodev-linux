/* cipher stuff */
#ifndef CRYPTODEV_INT_H
# define CRYPTODEV_INT_H

#include <linux/init.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/scatterlist.h>
#include <cryptodev.h>

#define PFX "cryptodev: "
#define dprintk(level,severity,format,a...)			\
	do {						\
		if (level <= cryptodev_verbosity)				\
			printk(severity PFX "%s[%u]: " format,	\
			       current->comm, current->pid,	\
			       ##a);				\
	} while (0)

extern int cryptodev_verbosity;

/* For zero copy */
int __get_userbuf(uint8_t *addr, uint32_t len, int write,
		int pgcount, struct page **pg, struct scatterlist *sg);
void release_user_pages(struct page **pg, int pagecount);

/* last page - first page + 1 */
#define PAGECOUNT(buf, buflen) \
        ((((unsigned long)(buf + buflen - 1) & PAGE_MASK) >> PAGE_SHIFT) - \
         (((unsigned long) buf               & PAGE_MASK) >> PAGE_SHIFT) + 1)


struct cipher_data
{
	int init; /* 0 uninitialized */
	int blocksize;
	int ivsize;
	struct {
		struct crypto_ablkcipher* s;
		struct cryptodev_result *result;
		struct ablkcipher_request *request;
		uint8_t iv[EALG_MAX_BLOCK_LEN];
	} async;
};

int cryptodev_cipher_init(struct cipher_data* out, const char* alg_name, uint8_t * key, size_t keylen);
void cryptodev_cipher_deinit(struct cipher_data* cdata);
ssize_t cryptodev_cipher_decrypt( struct cipher_data* cdata, struct scatterlist *sg1, struct scatterlist *sg2, size_t len);
ssize_t cryptodev_cipher_encrypt( struct cipher_data* cdata, struct scatterlist *sg1, struct scatterlist *sg2, size_t len);

void cryptodev_cipher_set_iv(struct cipher_data* cdata, void* iv, size_t iv_size);
int _cryptodev_cipher_decrypt(struct cipher_data* cdata, const void* ciphertext,
	size_t ciphertext_size, void* plaintext, size_t plaintext_size);
int _cryptodev_cipher_encrypt(struct cipher_data* cdata, const void* plaintext,
	size_t plaintext_size, void* ciphertext, size_t ciphertext_size);

/* hash stuff */
struct hash_data
{
	int init; /* 0 uninitialized */
	int digestsize;
	struct {
		struct crypto_ahash *s;
		struct cryptodev_result *result;
		struct ahash_request *request;
	} async;
};

int cryptodev_hash_final( struct hash_data* hdata, void* output);
ssize_t cryptodev_hash_update( struct hash_data* hdata, struct scatterlist *sg, size_t len);
ssize_t _cryptodev_hash_update( struct hash_data* hdata, const void* data, size_t len);
int cryptodev_hash_reset( struct hash_data* hdata);
void cryptodev_hash_deinit(struct hash_data* hdata);
int cryptodev_hash_init( struct hash_data* hdata, const char* alg_name, int hmac_mode, void* mackey, size_t mackeylen);

/* compatibility stuff */
#ifdef CONFIG_COMPAT
#include <linux/compat.h>

/* input of CIOCGSESSION */
struct compat_session_op {
	/* Specify either cipher or mac
	 */
	uint32_t	cipher;		/* cryptodev_crypto_op_t */
	uint32_t	mac;		/* cryptodev_crypto_op_t */

	uint32_t	keylen;
	compat_uptr_t	key;		/* pointer to key data */
	uint32_t	mackeylen;
	compat_uptr_t	mackey;		/* pointer to mac key data */

	uint32_t	ses;		/* session identifier */
};

/* input of CIOCCRYPT */
 struct compat_crypt_op {
	uint32_t	ses;		/* session identifier */
	uint16_t	op;		/* COP_ENCRYPT or COP_DECRYPT */
	uint16_t	flags;		/* no usage so far, use 0 */
	uint32_t	len;		/* length of source data */
	compat_uptr_t	src;		/* source data */
	compat_uptr_t	dst;		/* pointer to output data */
	compat_uptr_t	mac;		/* pointer to output data for hash/MAC operations */
	compat_uptr_t	iv;		/* initialization vector for encryption operations */
};

/* compat ioctls, defined for the above structs */
#define COMPAT_CIOCGSESSION    _IOWR('c', 102, struct compat_session_op)
#define COMPAT_CIOCCRYPT       _IOWR('c', 104, struct compat_crypt_op)

#endif /* CONFIG_COMPAT */

#endif /* CRYPTODEV_INT_H */
