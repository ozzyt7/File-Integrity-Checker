#include <stdio.h>
#include <openssl/evp.h>
#include <string.h>
#include <time.h>

int main(int argc, char *argv[]){
	if (argc < 2 || argc > 2){
		fprintf(stderr, "Error. Usage <%s> <filename>\n", argv[0]);
		return 0;
	}
	char input[3], c;

	while (1){
		printf("\nWelcome to the File Integrity Checker. Please see the options for the program below.\n\n[1] Store hash of file\n[2] Check integrity of file\n[3] Update stored hash of file\n\nInput: ");
		fgets(input, sizeof(input), stdin);

		if (feof(stdin)){
        	printf("\n\nEOF encountered.\n\n");
        	return 0;
    	}
    	if (strchr(input, '\n') == NULL){
        	while ((c = getchar()) != '\n' && c != EOF);
        	printf("\nInvalid Input. Please don't include spaces and choose either only 1, 2 or 3.\n");
        	continue;
    	}

	break;
	}

	switch (input[0] - '0'){
		case 1: {
			//calculate file hash and determine time and store filename, hash and time in storedHash file
			FILE *fptr, *fptrStored;
			unsigned char buffer[1024];
			size_t bytesToRead;
			EVP_MD_CTX *mdctx = EVP_MD_CTX_new(); //create digest context
			fptr = fopen(argv[1], "rb");

			if (!fptr){
				printf("Error opening file.\n");
				return 0;
			}
			fptrStored = fopen("storedHash.txt", "a");

			if (!fptrStored) {
				printf("Error opening storedHash file\n");
				return 0;
			}
				
			EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL); //initialize SHA-256 hash function
			while ((bytesToRead = fread(buffer, 1, sizeof(buffer), fptr)) > 0){   
				EVP_DigestUpdate(mdctx, buffer, bytesToRead); //calculate file hash by 1024 bytes 
			}
			unsigned char digest[EVP_MAX_MD_SIZE];
			unsigned int digestLen;

			EVP_DigestFinal_ex(mdctx, digest, &digestLen); //put calculated hash into digest buffer
			fprintf(fptrStored, "Filename: %s\nHash: ", argv[1]);

			for (unsigned int i = 0; i < digestLen; i++){
				fprintf(fptrStored, "%02x", digest[i]); //format hash data in hexadeciml and store in storedHash file
			}
			//get calender time and format it in Year-Month-Day Hour:Min:Sec
			time_t currTime = time(NULL);
        	struct tm  *ptrLocalTime = localtime(&currTime);
			char dateAndTime[30];
			strftime(dateAndTime, sizeof(dateAndTime), "%Y-%m-%d %H:%M:%S", ptrLocalTime);
			fprintf(fptrStored, "\nLast Modified: %s", dateAndTime);

			printf("Hash of %s added to storedHash file.\n\n", argv[1]);
			EVP_MD_CTX_free(mdctx);
			fprintf(fptrStored, "\n\n");  
			fclose(fptrStored);
			fclose(fptr);
			break;
		}
		case 2: { 
			//first calculate hash of file, then find stored hash in file and compare the two hashes
			FILE *fptr, *fptrStored;   
			unsigned char buffer[1024];
			size_t bytesToRead;
			EVP_MD_CTX *mdctx = EVP_MD_CTX_new(); 
			fptr = fopen(argv[1], "rb");

			if (!fptr){
				printf("Error opening file.\n");
				return 0;
			}
			fptrStored = fopen("storedHash.txt", "r");

			if (!fptrStored) {
				printf("Error opening storedHash file\n");
				return 0;
			}

			EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL); 
			while ((bytesToRead = fread(buffer, 1, sizeof(buffer), fptr)) > 0){
				EVP_DigestUpdate(mdctx, buffer, bytesToRead);
			}
			unsigned char digest[EVP_MAX_MD_SIZE];
			unsigned int digestLen;
			char hash[65];

			EVP_DigestFinal_ex(mdctx, digest, &digestLen); 
			fprintf(fptrStored, "Filename: %s\nHash: ", argv[1]);

			for (unsigned int i = 0; i < digestLen; i++){
				sprintf(hash + (i *2), "%02x", digest[i]);
			}
			hash[64] = '\0';
			char storedHash[1024], filename[1024];
			int isFound = 0;
			
			//locate stored hash
			while (fgets(filename, sizeof(filename), fptrStored) != NULL){
				if (filename[0] == 'F'){
					filename[strcspn(filename, "\n")] = '\0';
					if (strcmp(filename + 10, argv[1]) == 0){
						fgets(storedHash, sizeof(storedHash), fptrStored);
						storedHash[strcspn(storedHash, "\n")] = '\0';
						if (strcmp(storedHash + 6, hash) == 0){
							printf("No file tampering detected. Hashes are identical.\n\n");
							isFound++;
							break;
						}
						printf("File tampering detected. Hashes are not identical.\n\n");
						isFound++;
						break;
					}		
					else{
						continue;
					}		
				}	
				else{
					continue;
				}

			}
			if (!isFound){
				printf("File not found. Please ensure you added the hash of file to the storedHash file before checking integrity.\n\n");
			}
			EVP_MD_CTX_free(mdctx);
			fprintf(fptrStored, "\n");
			fclose(fptrStored);
			fclose(fptr);
			break;

		}
		case 3: {
			//first calculate hash of file then locate position of stored hash and overwrite with new calculated hash
			EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
			FILE *fptr, *fptrStored;
			size_t bytesToRead;

			fptr = fopen(argv[1], "rb");
			fptrStored = fopen("storedHash.txt", "r+");

			if (!fptr){
				printf("Error opening file\n");
			}

			if (!fptrStored){
				printf("Error opening hash file\n");
			}
			unsigned char buffer[1024];

			EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
			while ((bytesToRead = fread(buffer, 1, sizeof(buffer), fptr)) > 0){
				EVP_DigestUpdate(mdctx, buffer, bytesToRead);
			}
			time_t currTime = time(NULL);
        	struct tm  *ptrLocalTime = localtime(&currTime);
			char dateAndTime[30];
			strftime(dateAndTime, sizeof(dateAndTime), "%Y-%m-%d %H:%M:%S", ptrLocalTime);
			fprintf(fptrStored, "\nLast Modified: %s", dateAndTime);

			unsigned char digest[EVP_MAX_MD_SIZE];
			unsigned int digestLen;
			char line[1024];
			EVP_DigestFinal_ex(mdctx, digest, &digestLen); 
			int isFound = 0;
			
			while(fgets(line, sizeof(line), fptrStored) != NULL){
				if (line[0] == 'F'){
					line[strcspn(line, "\n")] = '\0';
					if (strcmp(line + 10, argv[1]) == 0){
						fgets(line, sizeof(line), fptrStored);
						long pos = ftell(fptrStored);
						fseek(fptrStored, (pos + 6) - strlen(line), SEEK_SET);
				
						for (int i = 0; i < digestLen; i++){
							fprintf(fptrStored, "%02x", digest[i]);
						}
						isFound++;
						fgets(line, sizeof(line), fptrStored);
						fgets(line, sizeof(line), fptrStored);
						long posLM = ftell(fptrStored);
						fseek(fptrStored, (posLM + 15) - strlen(line), SEEK_SET);
						fprintf(fptrStored, "%s", dateAndTime);
						printf("Hash of %s updated in storedHash file.\n\n", argv[1]);
						break;
					}
					else{
						continue;
					}
				}
				else{
					continue;
				}
			}
			if (!isFound){  
				printf("File not found. Please ensure you add the hash of file to stored hash file before updating file hash.\n\n");
            }

			EVP_MD_CTX_free(mdctx);
			fclose(fptrStored);
			fclose(fptr);
			break;
		}
		default:
			printf("\nInvalid Input. Please don't include spaces and choose either only 1, 2 or 3.\n\n");
			break;
	}

	return 1;
}
