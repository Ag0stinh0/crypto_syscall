/**
 * 16507915 - Agostinho Sanches de Araujo
 * 16023905 - Evandro Douglas Capovilla Junior
 * 16105744 - Lucas Tenani Felix Martins
 * 16124679 - Pedro Andrade Caccavaro
 * 15248354 - Pedro Angelo Catalini
 */

#include <linux/init.h>    // Macros used to mark up functions e.g. __init __exit
#include <linux/module.h>  // Core header for loading LKMs into the kernel
#include <linux/device.h>  // Header to support the kernel Driver Model
#include <linux/kernel.h>  // Contains types, macros, functions for the kernel
#include <linux/fs.h>      // Header for the Linux file system support
#include <linux/uaccess.h> // Required for the copy to user function
#include <linux/mutex.h>   /// Required for the mutex functionality
#include <linux/scatterlist.h>
#include <linux/crypto.h>
//#include <crypto/internal/hash.h> // Maybe
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <linux/err.h>
#include <linux/string.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/moduleparam.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <linux/stat.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>
#include <linux/vmalloc.h>

#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 16


static char *key = "0123456789ABCDEF";

int cipherOperation(char *plaintext, char *encrypted, int nbytes, int option);

asmlinkage ssize_t sys_write_crypt (int fd, void *buf, size_t nbytes){ // 333
	int buffer_ptr, byte_count, ret_cypher;
	char* crypt_buf;
	char* plaintext;
	char* encrypted;
	size_t size_final_block, ret_file;
	mm_segment_t fs;
	
	printk(KERN_INFO "Crypto_Syscall: fd=%d size=%d\n",fd,(int)nbytes);
	
	crypt_buf = (char*) buf;
	buffer_ptr = 0;
	ret_file = 0;
 	size_final_block = AES_BLOCK_SIZE * ((nbytes - 1) / AES_BLOCK_SIZE) + AES_BLOCK_SIZE;
	
	encrypted = NULL;
	plaintext = (char*) vmalloc(size_final_block);
	encrypted = (char*) vmalloc(size_final_block);
	
	
	fs = get_fs();
	set_fs(KERNEL_DS);
	
	for (byte_count = 0; byte_count < nbytes; byte_count++)
		plaintext[byte_count] = crypt_buf[byte_count + buffer_ptr];
	for (byte_count = byte_count; byte_count < size_final_block; byte_count++)
		plaintext[byte_count] = 0;
		
	ret_cypher = cipherOperation(plaintext, encrypted, size_final_block, 1);
	if (ret_cypher)
		goto out;
	
	ret_file += sys_write(fd, encrypted, size_final_block);
	
	buffer_ptr += nbytes;
	
out:
	if (encrypted != NULL)
		vfree(encrypted);
	if (plaintext != NULL)
		vfree(plaintext);
		
	set_fs(fs);
	return ret_file;
}



asmlinkage ssize_t sys_read_crypt(int fd, void *buf, size_t nbytes){ //334
	int buffer_ptr, byte_count, ret_cypher;
	char* crypt_buf;
	char* decrypted;
	char* encrypted;
	size_t size_final_block, ret_file;
	mm_segment_t fs;
	
	printk(KERN_INFO "Crypto_Syscall: fd=%d size=%d\n",fd,(int)nbytes);
	
	crypt_buf = (char*) buf;
	buffer_ptr = 0;
	ret_file = 0;
 	size_final_block = AES_BLOCK_SIZE * ((nbytes - 1) / AES_BLOCK_SIZE) + AES_BLOCK_SIZE;
 	
 	fs = get_fs();
 	set_fs(KERNEL_DS);
 	
 	decrypted = NULL;
	decrypted = (char*) vmalloc(size_final_block);
	encrypted = (char*) vmalloc(size_final_block);
	
	ret_cypher = cipherOperation(decrypted, encrypted, size_final_block, 2);
	if (ret_cypher)
		goto out;
		
	for (byte_count = 0; byte_count < nbytes; byte_count++)
		crypt_buf[byte_count + buffer_ptr] = decrypted[byte_count];
	
	buffer_ptr += nbytes;
	
out:
	if (encrypted != NULL)
		vfree(encrypted);
	if (decrypted != NULL)
		vfree(decrypted);
		
	set_fs(fs);
	return ret_file;
}


int cipherOperation(char *plaintext, char *encrypted, int nbytes, int option)  
{     
    printk(KERN_INFO "Crypto_Syscall: Encrypt function\n");
    struct crypto_skcipher *skcipher = NULL;
    struct skcipher_request *skcipher_req = NULL;
    
    struct scatterlist scatter_plaintext;
    struct scatterlist scatter_crypt;
    char *crypt_result = NULL;
    char *result_data = NULL;
    
    char *local_key = NULL;
    char *aux;
    
    int ret = -EFAULT;
    int i;
    
    skcipher = crypto_alloc_skcipher("ecb(aes)", 0,0);
    if (IS_ERR(skcipher)){
    	printk(KERN_INFO "Crypto_Syscall: ERROR - Failed to allocate skcipher\n");
    	return PTR_ERR(skcipher);
    	goto out;
    }
    
    skcipher_req = skcipher_request_alloc(skcipher, GFP_KERNEL);
    if (!skcipher_req){
    	printk(KERN_INFO "Crypto_Syscall: ERROR - Failed to request skcipher\n");
    	ret = -ENOMEM;
    	goto out;
    }
    
    local_key = vmalloc(AES_KEY_SIZE);
    if (!local_key){
    	printk(KERN_INFO "Crypto_Syscall: ERROR - Failed to allocate key\n");
    	goto out;
    }
    
    for (i = 0; i<AES_KEY_SIZE; i++)
    	local_key[i] = key[i];
 	
 	
 	ret = crypto_skcipher_setkey(skcipher, local_key, AES_KEY_SIZE);
 	if (ret){
 		printk(KERN_INFO "Crypto_Syscall: ERROR - Failed to set key\n");
    	ret = -EAGAIN;
    	goto out;
 	}
 	
 	crypt_result = vmalloc(nbytes);
 	if (!crypt_result){
 		printk(KERN_INFO "Crypto_Syscall: ERROR - Failed to allocate crypt_result\n");
    	goto out;
 	}
 	
 	if (option == 1){
 		sg_init_one(&scatter_plaintext, plaintext, nbytes);
 		sg_init_one(&scatter_crypt, crypt_result, nbytes);
 		
 		skcipher_request_set_crypt(skcipher_req, &scatter_plaintext, &scatter_crypt, nbytes, NULL);
 		
 		ret = crypto_skcipher_encrypt(skcipher_req);
 	} else if (option == 2){
 		sg_init_one(&scatter_plaintext, crypt_result, nbytes);
 		sg_init_one(&scatter_crypt, encrypted, nbytes);
 		
 		skcipher_request_set_crypt(skcipher_req, &scatter_crypt, &scatter_plaintext, nbytes, NULL);
 		
 		ret = crypto_skcipher_encrypt(skcipher_req);
 	}
 	
 	if (ret){
 		printk(KERN_INFO "Crypto_Syscall: ERROR - Cypher Operation failed\n");
    	goto out;
 	}
 	
 	if (option == 1){
 		result_data = sg_virt(&scatter_crypt);
 		for(i = 0; i < nbytes; i++)
 			encrypted[i] = result_data[i];
 	}else if( option == 2){
 		result_data = sg_virt(&scatter_plaintext);
 		for(i = 0; i < nbytes; i++)
 			plaintext[i] = result_data[i];
 	}
 	
 	printk(KERN_INFO "Crypto_Syscall: RESULT - ");
 	aux = result_data;
	while (nbytes--){
		printk(KERN_INFO "%02x ", *aux);
		aux++;
	}
	printk(KERN_INFO "\n");
	
out:
	if (skcipher)
        crypto_free_skcipher(skcipher);
    if (skcipher_req)
        skcipher_request_free(skcipher_req);
    if (local_key)
    	vfree(local_key);
    if (crypt_result)
        vfree(crypt_result);
        
    return ret;
}
