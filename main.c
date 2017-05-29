//
//  main.c
//  Security-TermProject
//
//  Created by Barış Yamansavaşçılar on 30.04.2017.
//  Copyright © 2017 Barış Yamansavaşçılar. All rights reserved.
//

#include "aesAlgorithm.h"
#include "sha1.h"
#include "rsa.h"
#include <dirent.h>
#include <time.h>
#include <string.h>



uint8_t key[] = {
    0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13,
    0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b,
    0x1c, 0x1d, 0x1e, 0x1f};

uint8_t *userKey;
char privateDirectory[200];

void encryption(const char *filePath){
    uint8_t encryptedOutput[16]; // 128-bit output
    uint8_t *w; // expanded key
    if (userKey){
        switch (sizeof(userKey)) {
            default:
            case 16: Nk = 4; Nr = 10; break;
            case 24: Nk = 6; Nr = 12; break;
            case 32: Nk = 8; Nr = 14; break;
        }
        
        w = malloc(Nb*(Nr+1)*4);
        
        key_expansion(userKey, w);
    }else{
        switch (sizeof(key)) {
            default:
            case 16: Nk = 4; Nr = 10; break;
            case 24: Nk = 6; Nr = 12; break;
            case 32: Nk = 8; Nr = 14; break;
        }
        
        w = malloc(Nb*(Nr+1)*4);
        
        key_expansion(key, w);
    }
    
    
    FILE *originalFile;
    originalFile = fopen(filePath, "rb+");
    uint8_t readByte[16];
    
    
    long int tp;
    
    if (originalFile) {
        tp = ftell(originalFile);
        fseek(originalFile, tp, SEEK_SET);
        while (fread(&readByte, 1, 16, originalFile)) {
            fseek(originalFile, tp, SEEK_SET);
            cipher(readByte /* in */, encryptedOutput /* out */, w /* expanded key */);
            fwrite(encryptedOutput, 1, 16, originalFile); // same documnet is encrypted
            tp = ftell(originalFile);
        }
    }
    fclose(originalFile);
}

void decryption(const char *filePath){
    
    uint8_t *w; // expanded key
    
    if (userKey){
        switch (sizeof(userKey)) {
            default:
            case 16: Nk = 4; Nr = 10; break;
            case 24: Nk = 6; Nr = 12; break;
            case 32: Nk = 8; Nr = 14; break;
        }
        
        w = malloc(Nb*(Nr+1)*4);
        
        key_expansion(userKey, w);
    }else{
        switch (sizeof(key)) {
            default:
            case 16: Nk = 4; Nr = 10; break;
            case 24: Nk = 6; Nr = 12; break;
            case 32: Nk = 8; Nr = 14; break;
        }
        
        w = malloc(Nb*(Nr+1)*4);
        
        key_expansion(key, w);
    }

    
    FILE *encryptedOne = fopen(filePath, "rb+");
    if (!encryptedOne) {
        perror("encrypted File cannot be opened");
    }
    uint8_t readByte[16];
    uint8_t output[16];
    long int tp;
    
    tp = ftell(encryptedOne);
    fseek(encryptedOne, tp, SEEK_SET);
    while (fread(&readByte, 1, 16, encryptedOne)) {
        fseek(encryptedOne, tp, SEEK_SET);
        inv_cipher(readByte, output, w);
        fwrite(output, 1, 16, encryptedOne); // bu sekilde calismasi lazim
        tp = ftell(encryptedOne);
    }
    fclose(encryptedOne);
}

void createPublicPrivateKeyPairs(int id){
    
    int p, q, n, phi, e, d;
    srand(time(NULL));
    while(1) {
        p = randPrime(SINGLE_MAX);
        printf("Got first prime factor, p = %d ... ", p);
        //getchar();
        
        q = randPrime(SINGLE_MAX);
        printf("Got second prime factor, q = %d ... ", q);
        //getchar();
        
        n = p * q;
        printf("Got modulus, n = pq = %d ... ", n);
        if(n < 128) {
            printf("Modulus is less than 128, cannot encode single bytes. Trying again ... ");
            //getchar();
        }
        else break;
    }
    phi = (p - 1) * (q - 1);
    printf("Got totient, phi = %d ... ", phi);
    //getchar();
    
    e = randExponent(phi, EXPONENT_MAX);
    printf("Chose public exponent, e = %d\nPublic key is (%d, %d) ... ", e, e, n);
    //getchar();
    
    d = inverse(e, phi);
    printf("Calculated private exponent, d = %d\nPrivate key is (%d, %d) ... ", d, d, n);
    char publicKeyE[25];
    char publicPrivateN[25];
    char privateKeyD[25];
    sprintf(publicKeyE, "%d", e);
    sprintf(publicPrivateN, "%d",n);
    sprintf(privateKeyD, "%d",d);
    
    char *thePublicKey = malloc(strlen(publicKeyE)+strlen(publicPrivateN)+1+1);
    char *thePrivateKey = malloc(strlen(privateKeyD)+1); // do not confuse with symmetric key! this is for rsa!
    
    
    strcpy(thePublicKey, publicKeyE);
    strcat(thePublicKey, " ");
    strcat(thePublicKey, publicPrivateN);
    strcpy(thePrivateKey, privateKeyD);
    
    
    FILE *publicKeyFile = fopen("publicKeys", "ab");
    if (!publicKeyFile) {
        perror("There is an important error");
        EXIT_FAILURE;
    }
    FILE *privateKeyFile = fopen(privateDirectory, "ab");
    if (!privateKeyFile) {
        perror("There is an important error");
        EXIT_FAILURE;
    }
    
    uint8_t *w; // expanded key
    
    switch (sizeof(key)) {
        default:
        case 16: Nk = 4; Nr = 10; break;
        case 24: Nk = 6; Nr = 12; break;
        case 32: Nk = 8; Nr = 14; break;
    }
    
    w = malloc(Nb*(Nr+1)*4);
    key_expansion(key, w);
    uint8_t encryptedPrivateKey[16];
    
    char pairID[16];
    sprintf(pairID, "%d",id);
    char *thePairID = malloc(strlen(pairID)+1);
    strcpy(thePairID, pairID);
    
    cipher((uint8_t *)thePrivateKey, encryptedPrivateKey, w);
    
    
    fwrite(thePairID, 1, 16, publicKeyFile);
    fwrite((uint8_t *)thePublicKey, 1, 16, publicKeyFile);
    
    fwrite(thePairID, 1, 16, privateKeyFile);
    fwrite(encryptedPrivateKey, 1, 16, privateKeyFile);
    
    fclose(publicKeyFile);
    fclose(privateKeyFile);
}

//
int authentication(int e, int d, int n){
    int *encoded, *decoded;
    char testString[16] = "123456";
    
    int len = strlen(testString);
    int bytes;
    if(n >> 21) bytes = 3;
    else if(n >> 14) bytes = 2;
    else bytes = 1;
    
    
    encoded = encodeMessage(len, bytes, testString, e, n); // encoded by using public-key
    decoded = decodeMessage(len/bytes, bytes, encoded, d, n);
    char comparedText[16];
    int counter = 0;
    for (int i=0; i<len; i++) {
        for(int j = 0; j < bytes; j++){
            if (counter < 16) {
                comparedText[counter] = decoded[i*bytes + j];
            }
            counter++;
        }
    }
    
    free(encoded);
    free(decoded);
    if (strcmp(testString, comparedText) == 0) {
        printf("\nIt is work!\n");
        return 1;
    }else{
        printf("\nWrong password!\n");
        return 0;
    }
    
    
}




int getParametersForAuthentication(char *id, int intention){
    
    FILE *privateKeyFile = fopen(privateDirectory, "rb");
    if (!privateKeyFile) {
        perror("There is an important error");
        EXIT_FAILURE;
    }
    FILE *publicKeyFile = fopen("publicKeys", "rb");
    if (!privateKeyFile) {
        perror("There is an important error");
        EXIT_FAILURE;
    }
    
    uint8_t *w; // expanded key
    
    switch (sizeof(key)) {
        default:
        case 16: Nk = 4; Nr = 10; break;
        case 24: Nk = 6; Nr = 12; break;
        case 32: Nk = 8; Nr = 14; break;
    }
    
    w = malloc(Nb*(Nr+1)*4);
    key_expansion(key, w);
    uint8_t decryptedPrivateKey[16];
    uint8_t readByte[16];
    
    long tp;
    tp = ftell(privateKeyFile);
    fseek(privateKeyFile, tp, SEEK_SET);
    int isFound = 0;
    while (fread(&readByte, 1, 16, privateKeyFile) && strcmp((char *)readByte, id)!=0) {
        tp = ftell(privateKeyFile);
        fseek(privateKeyFile, tp, SEEK_SET);
    }
    if (strcmp((char *)readByte, id)==0) {
        isFound = 1;
        printf("ID has been found: %s ",readByte);
    }
    char eValue[20];
    char nValue[20];
    fread(&readByte, 1, 16, privateKeyFile);
    int d,e,n;
    inv_cipher(readByte, decryptedPrivateKey, w);
    
    if (intention == 2) {
        return isFound;
    }
    
    if (isFound) {
        printf("\n Reversed private key (d value): %s\n",decryptedPrivateKey); //actually the d value
        d = atoi((char *)decryptedPrivateKey);
        fseek(publicKeyFile, tp, SEEK_SET);
        fread(&readByte, 1, 16, publicKeyFile); //id
        fread(&readByte, 1, 16, publicKeyFile); //public key
        int part = 1;//first part of public key
        int counter = 0;
        for (int i=0; i<16; i++) {
            if (part == 1 && (char *)readByte[i]!=' ') {
                counter++;
                eValue[i] = readByte[i];
            }else if ((char *)readByte[i] == ' '){
                counter++;
                part = 2;
            }else{
                nValue[i-counter] = readByte[i]; //checked for overflow
            }
        }
        e = atoi(eValue);
        n = atoi(nValue);
        printf("\n The public key: %s\n",readByte);
        
        
    }else{
        printf("Invalid id no. Please enter the correct id number:\n");
        return 0;
    }
    
    fclose(privateKeyFile);
    fclose(publicKeyFile);
    
    if (authentication(e, d, n)) {
        return 1;
    }else{
        return 0;
    }
    
}


void handleFile(char *filePath, int selection){
    clock_t start, end;
    if (selection == 1) {
        start = clock();
        encryption(filePath);
        end = clock();
        printf( "Encryption duration is %f seconds\n", (end-start)/(double)CLOCKS_PER_SEC );
    }else{
        start = clock();
        decryption(filePath);
        end = clock();
        printf( "Decryption duration is %f seconds\n", (end-start)/(double)CLOCKS_PER_SEC );
    }
    
}


void listdir(const char *name, int level, int selection)
{
    DIR *dir;
    struct dirent *entry;
    
    if (!(dir = opendir(name)))
        return;
    if (!(entry = readdir(dir)))
        return;
    
    do {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 || strcmp(entry->d_name, ".DS_Store")==0 || strcmp(entry->d_name, "._.DS_Store")==0 || strcmp(entry->d_name, ". -DS_Store")==0)
            continue;
        
        char path[1024];
        int len = snprintf(path, sizeof(path)-1, "%s/%s", name, entry->d_name);
        path[len] = 0;
        printf("%*s[%s]\n", level*2, "", entry->d_name);
        if (entry->d_type == DT_DIR) {
            listdir(path, level + 1, selection);
        }
        else{ //if not folder then handle
            
            printf("Processing ->%*s- %s\n", level*2, "", entry->d_name);
            //handleFile(entry->d_name, path);
            handleFile(path, selection);
            
        }
    } while ((entry = readdir(dir)));
    closedir(dir);
}



int main(int argc, const char * argv[]) {
    
    printf("Welcome to the Encryption/Decryption System\n");
    char password[25];
    char hashResult[21];
    char hexresult[41];
    clock_t start, end;
    //run(byteArray); //using symmetric encryption/decryption
    FILE *passwordHashFile = fopen("passwordFile", "r");
    if (!passwordHashFile) {
        printf("There is no user password in the system. Please create your new including at least 8 characters password:\n");
        do {
            scanf("%s",password);
            if (strlen(password) < 8) {
                printf("Your password should be at least 8 characters. Please re-enter new password:\n");
            }
        } while (strlen(password) < 8);
        printf("Your password has been created successfully!\n");
        fclose(passwordHashFile);
        FILE *passwordHashFile = fopen("passwordFile", "a");
        printf("\n");
        SHA1(hashResult, password, strlen(password));
        for(size_t offset = 0; offset < 20; offset++) {
            sprintf( ( hexresult + (2*offset)), "%02x", hashResult[offset]&0xff);
        }
        fprintf(passwordHashFile, "%s",hexresult);
        fclose(passwordHashFile);
        
    }else{
        char readHashFromFile[40];
        
        printf("For the encryption, please enter your password: \n");
        do {
            scanf("%s",password);
            fscanf(passwordHashFile,"%s",readHashFromFile);
            SHA1(hashResult, password, strlen(password));
            for(size_t offset = 0; offset < 20; offset++) {
                sprintf( ( hexresult + (2*offset)), "%02x", hashResult[offset]&0xff);
            }
            if (strcmp(readHashFromFile, hexresult) == 0) {
                printf("Access granted! \n");
            }else{
                printf("Wrong password! Please re-enter your password:\n");
            }
        } while (!(strcmp(readHashFromFile, hexresult) == 0));
        fclose(passwordHashFile);
    }
    
    int selection;
    char directory[100]; //for interoperability, it is defined statically
    
    FILE *publicKeysFile = fopen("publicKeys", "r");
    char id[50];
    
    if (!publicKeysFile) {
        fclose(publicKeysFile);
        printf("You don't have any public-private key pairs. Please enter an id for your new key pair for future authentication process:\n ");
        scanf("%s",id);
        printf("Please indicate a empty file path that will includes your private key:\n");
        scanf("%s",privateDirectory);
        createPublicPrivateKeyPairs(atoi(id));
        printf("Your public-private key pair has been created!");
    }else{
        fclose(publicKeysFile);
        printf("For authentication procedure, please enter your one of public-private key pair id: \n");
        scanf("%s",id);
        printf("Please enter your directory including your private key:\n");
        scanf("%s",privateDirectory);
        
        while (!getParametersForAuthentication(id, 1)) {
            //printf("There is an error for authentication\n");
            scanf("%s",id);
            printf("Please enter your directory including your private key:\n");
            scanf("%s",privateDirectory);
        }
        
        
    }
 
    
    do {
        printf("Please enter the number indicating the process that you would like to perform: \n\n");
        printf("1 - Encryption\n");
        printf("2 - Decryption\n");
        printf("3 - Change Password\n");
        printf("4 - Create new private-public key pair\n");
        printf("5 - Exit\n");
        char temp[40];
        scanf("%s",temp);
        selection = atoi(temp);
        switch (selection) {
            case 1:
                
                printf("Please enter the folder path:\n");
                scanf("%s",directory);
                listdir(directory, 2, selection);
                
                break;
            case 2:
               
                printf("For decryption, please enter the folder path:\n");
                scanf("%s",directory);
                listdir(directory, 2, selection);
                break;
            case 3:
                printf("Please enter your current password: \n");
                
                char readHashFromFile[40];
                FILE *passwordHashFile = fopen("passwordFile", "r");
                if (passwordHashFile) {
                    do {
                        scanf("%s",password);
                        fscanf(passwordHashFile,"%s",readHashFromFile);
                        SHA1(hashResult, password, strlen(password));
                        for(size_t offset = 0; offset < 20; offset++) {
                            sprintf( ( hexresult + (2*offset)), "%02x", hashResult[offset]&0xff);
                        }
                        if (strcmp(readHashFromFile, hexresult) == 0) {
                            printf("Correct! Now you can change your password: \n");
                        }else{
                            printf("Wrong password! Please re-enter your current password:\n");
                        }
                    } while (!(strcmp(readHashFromFile, hexresult) == 0));
                }
                fclose(passwordHashFile);
                passwordHashFile = fopen("passwordFile", "w");
                printf("Please enter your new password: \n");
                
                do {
                    scanf("%s",password);
                    if (strlen(password) < 8) {
                        printf("Your password should be at least 8 characters. Please re-enter new password:\n");
                    }
                } while (strlen(password) < 8);
                printf("Your new password has been created successfully!\n");
                fclose(passwordHashFile);
                passwordHashFile = fopen("passwordFile", "a");
                printf("\n");
                SHA1(hashResult, password, strlen(password));
                for(size_t offset = 0; offset < 20; offset++) {
                    sprintf( ( hexresult + (2*offset)), "%02x", hashResult[offset]&0xff);
                }
                fprintf(passwordHashFile, "%s",hexresult);
                fclose(passwordHashFile);
                
                break;
            case 4:
                printf("Please enter your private key directory to store encrypted private key:\n");
                scanf("%s",privateDirectory);
                printf("Please select your new id for new private-public key pair:\n");
                scanf("%s",id);
                
                while (getParametersForAuthentication(id,2)) {
                    printf("Your id is already created! Please enter different id:");
                    scanf("%s",id);
                }
                
                createPublicPrivateKeyPairs(atoi(id));
                printf("Your new public-private key pair has been created!\n");
                
            default:
                if(selection != 5)
                break;
        }
        
        
    } while (selection != 5);
    
    
    printf("Goodbye :)\n");
    
    
    
    return 0;
}

