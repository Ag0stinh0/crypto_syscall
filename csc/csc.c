/**
 * 16507915 - Agostinho Sanches de Araujo
 * 16023905 - Evandro Douglas Capovilla Junior
 * 16105744 - Lucas Tenani Felix Martins
 * 16124679 - Pedro Andrade Caccavaro
 * 15248354 - Pedro Angelo Catalini
 */

#include <crypto/hash.h>
#include <crypto/skcipher.h>

#include <linux/crypto.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/random.h>
#include <linux/scatterlist.h>
#include <linux/sched.h>
#include <linux/stat.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/unistd.h>
#include <linux/vmalloc.h>

#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 16

static char *key = "0123456789ABCDEF";

static void printHex(unsigned char *, unsigned int);
static int cipherOperation(char *, int, char *, int option);

asmlinkage ssize_t sys_write_crypt(int fd, void *buf, size_t size)
{
	char* buf_copy;
	int byte_count;
	char* plaintext;
	char* encrypted;
	ssize_t ret;
	mm_segment_t fs;
	int cipher_ret;
	size_t final_block_size;

	ret = 0;
	buf_copy = (char*)buf;
	final_block_size = AES_BLOCK_SIZE * ((size - 1) / AES_BLOCK_SIZE) + AES_BLOCK_SIZE;

	printk(KERN_INFO "Crypto_Syscall: Params fd=%d, size=%d, total=%d\n", fd, (int)size, final_block_size);

	if (fd < 0) return fd;
	if (size <= 0) return size;

    fs = get_fs();
    set_fs(KERNEL_DS);

	printk(KERN_INFO "Crypto_Syscall: Data allocate\n");
	encrypted = NULL;
	plaintext = (char*) vmalloc(final_block_size);
	if (plaintext == NULL) goto out;
	encrypted = (char*) vmalloc(final_block_size);
	if (encrypted == NULL) goto out;

    printk(KERN_INFO "Crypto_Syscall: Copying buffer\n");
    for (byte_count = 0; byte_count < size;byte_count++) plaintext[byte_count] = buf_copy[byte_count];
    for (/*PADDING*/;byte_count < final_block_size; byte_count++) plaintext[byte_count] = 0;

    printk(KERN_INFO "Crypto_Syscall: Start encryption\n");
    cipher_ret = cipherOperation(plaintext, final_block_size, encrypted, 1);
    if (cipher_ret) { goto out; }

    printk(KERN_INFO "Crypto_Syscall: Writing file\n");
    ret += sys_write(fd, encrypted, final_block_size);

out:
	if (encrypted != NULL) vfree(encrypted);
	if (plaintext != NULL) vfree(plaintext);

    set_fs(fs);
    return ret;
}

asmlinkage ssize_t sys_read_crypt(int fd, void *buf, size_t size)
{
	char* buf_copy;
	int byte_count;
	char* encrypted;
	char* plaintext;
	ssize_t ret, sys_ret;
	mm_segment_t fs;
	int cipher_ret;
	size_t final_block_size;

	ret = 0;
	buf_copy = (char*)buf;
	final_block_size = AES_BLOCK_SIZE * ((size - 1) / AES_BLOCK_SIZE) + AES_BLOCK_SIZE;

	printk(KERN_INFO "Crypto_Syscall: Params fd=%d, size=%d, total=%d\n", fd, (int)size,final_block_size);

	if (fd < 0) return fd;
	if (size <= 0) return size;

	fs = get_fs();
	set_fs(KERNEL_DS);

	printk(KERN_INFO "Crypto_Syscall: Data allocate\n");
	plaintext = NULL;
	encrypted = (char*) vmalloc(final_block_size);
	if (encrypted == NULL) goto out;
	plaintext = (char*) vmalloc(final_block_size);
	if (plaintext == NULL) goto out;


    printk(KERN_INFO "Crypto_Syscall: Reading file\n");
    sys_ret = sys_read(fd, encrypted, final_block_size);
    if (sys_ret < final_block_size) {printk(KERN_INFO "Crypto_Syscall: Found incomplete block..."); goto out; }

    printk(KERN_INFO "Crypto_Syscall: Start decryption\n");
    cipher_ret = cipherOperation(plaintext, final_block_size, encrypted, 2);
    if (cipher_ret) { goto out; }

    printk(KERN_INFO "Crypto_Syscall: Copying buffer\n");
    for (byte_count = 0; byte_count < size; byte_count++) buf_copy[byte_count] = plaintext[byte_count];

    ret += sys_ret;


out:
	if (encrypted != NULL) vfree(encrypted);
	if (plaintext != NULL) vfree(plaintext);

    set_fs(fs);
    return ret;
}

static void printHex(unsigned char *buf, unsigned int len) {
		unsigned char* aux = buf;
        while (len--) { printk(KERN_INFO "Crypto_Syscall: DEBUG - 0x%02x ", *aux); aux++; }
        printk("\n");
}

static int cipherOperation(char *plaintext, int size, char *cyphertext, int option)
{
    struct crypto_skcipher *skcipher = NULL;
    struct skcipher_request *skcipher_req = NULL;
    struct scatterlist scatter_plaintext;
    struct scatterlist scatter_crypt;
    char *crypt_res = NULL;
    char *resultdata = NULL;
    char *local_key = NULL;

    int ret = -EFAULT;
    int i;

    skcipher = crypto_alloc_skcipher("ecb(aes)", 0, 0);
    if (IS_ERR(skcipher)) {
        printk(KERN_INFO "Crypto_Syscall: Could not allocate skcipher handle (%ld)\n", PTR_ERR(skcipher));
        return PTR_ERR(skcipher);
        goto out;
    }

    skcipher_req = skcipher_request_alloc(skcipher, GFP_KERNEL);
    if (!skcipher_req) {
        printk(KERN_INFO "Crypto_Syscall: Could not allocate skcipher request\n");
        ret = -ENOMEM;
        goto out;
    }

    local_key = vmalloc(AES_KEY_SIZE);
    if (!local_key) {
        printk(KERN_INFO "Crypto_Syscall: Could not allocate key\n");
        goto out;
    }

    for(i=0; i<AES_KEY_SIZE; i++) local_key[i] = key[i];

    if (crypto_skcipher_setkey(skcipher, local_key, AES_KEY_SIZE)) {
        printk(KERN_INFO "Crypto_Syscall: Key could not be set\n");
        ret = -EAGAIN;
        goto out;
    }

    crypt_res = vmalloc(size);
    if (!crypt_res) {
        printk(KERN_INFO "Crypto_Syscall: Could not allocate criptograf\n");
        goto out;
    }

    if (option == 1) {
        sg_init_one(&scatter_plaintext, plaintext, size);
        sg_init_one(&scatter_crypt, crypt_res, size);

        skcipher_request_set_crypt(skcipher_req, &scatter_plaintext, &scatter_crypt, size, NULL);

    	ret = crypto_skcipher_encrypt(skcipher_req);
	} else if (option == 2) {
        sg_init_one(&scatter_plaintext, crypt_res,  size);
        sg_init_one(&scatter_crypt, cyphertext, size);

        skcipher_request_set_crypt(skcipher_req, &scatter_crypt, &scatter_plaintext, size, NULL);

    	ret = crypto_skcipher_decrypt(skcipher_req);
	} else {
		ret = -1;
	}

    if (ret) {
        printk(KERN_INFO "Crypto_Syscall: ERROR - encryption\n");
        goto out;
    }

    if (option == 1) {
        resultdata = sg_virt(&scatter_crypt);
	} else if (option == 2) {
        resultdata = sg_virt(&scatter_plaintext);
	}

    printHex(resultdata, size);

    if (option == 1) {
        for(i=0;i<size;i++) cyphertext[i] = resultdata[i];
	} else if (option == 2) {
        for(i=0;i<size;i++) plaintext[i] = resultdata[i];
	}

    out:
    if (skcipher)
        crypto_free_skcipher(skcipher);
    if (skcipher_req)
        skcipher_request_free(skcipher_req);
    if (local_key)
    	vfree(local_key);
    if (crypt_res)
        vfree(crypt_res);

    return ret;
}
