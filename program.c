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
	int fd;
	ssize_t ret;
	char file_content[200] = "", aux[200], target_file[100], final[200] = "";

	printf("[+] Enter the file name to encrypt: ");
	scanf("%[^\n]", target_file);
    fd = open(target_file, O_RDONLY, 0666);
    while(read(fd, aux, sizeof(char))){
    	strcat(file_content,aux);
    }
    close(fd);

	printf("[~] File content (pre-encrypt):\n");
	printf("%s",file_content);

	fd = open("secret_file.txt", O_WRONLY|O_CREAT, 0666);
	ret = syscall(333, fd, file_content, strlen(file_content));
	if (ret < 0){
		printf("[-] Operation Write Failed\n");
		return -1;
	}
	close(fd);


	fd = open("secret_file.txt", O_RDONLY|O_CREAT, 0666);

	char crypt_rec[1600];
	FILE *fileOp = fopen("secret_file.txt", "r");
	fread(crypt_rec, 1, strlen(file_content)*16, fileOp);
	printf("[~] File content (encrypted):\n%s", crypt_rec);
	fclose(fileOp);
	printf("\n");

	ret = syscall(334, fd, final, strlen(file_content));
	if (ret < 0){
		printf("[-] Operation Read Failed\n");
		return -1;
	}
	final[strlen(file_content)] = '\0';


	close(fd);
	printf("[~] Decrypted content: \n");
	printf("%s\n", final);

	return 0;
}
