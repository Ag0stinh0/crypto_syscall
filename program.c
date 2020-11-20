/**
 * 16507915 - Agostinho Sanches de Araujo
 * 16023905 - Evandro Douglas Capovilla Junior
 * 16105744 - Lucas Tenani Felix Martins
 * 16124679 - Pedro Andrade Caccavaro
 * 15248354 - Pedro Angelo Catalini
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

int main(){
	int fd, file_size;
	ssize_t ret;
	char file_content[200] = "", target_file[100], final[200];

	// Get the name of the target file to encrypt and save the content
	printf("[+] Enter the file name to encrypt: ");
	scanf("%[^\n]", target_file);
	fd = open(target_file, O_RDONLY, 0666);
	while(read(fd, aux, sizeof(char))){
		strcat(file_content,aux);
	}
	close(fd);

	printf("[~] Reading file...\n");
	file_size = strlen(file_content);

	printf("[+] Calling Write Crypt\n");
	// create the secret file and use the sycall to store the cypher content
	fd = open("secret_file.txt", O_WRONLY|O_CREAT, 0666);
	ret = syscall(333, fd, file_content, strlen(file_content));
	if (ret < 0){
		printf("Operation Write Failed\n");
		return -1;
	}
	close(fd);

	printf("[!] Secret File created\n");
	printf("[~] Calling Read Crypt\n");
	// use syscall to decypher the content and print
	fd = open("secret_file.txt", O_RDONLY|O_CREAT, 0666);
	ret = syscall(334, fd, final, strlen(file_content));
	if (ret < 0){
		printf("Operation Write Failed\n");
		return -1;
	}
	printf("[*] Decrypted file Content: %s\n", final);
	return 0;
}
