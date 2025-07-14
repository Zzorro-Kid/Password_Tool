#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>

#define MAX_LEN 256

void generate_password(int length) {
    char password[MAX_LEN];
    const char charset[] = "abcdefghijklmnopqrstuvwxyz"
                           "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                           "0123456789"
                           "!@#$^&*()-_=+[]{}";

    for (int i = 0; i < length; i++) {
        int key = rand() % (sizeof(charset) - 1);
        password[i] = charset[key];
    }

    password[length] = '\0';
    printf("Your generated password is: %s\n", password);
}

void print_hash(unsigned char *hash, unsigned int len) {
    for (unsigned int i = 0; i < len; i++)
        printf("%02x", hash[i]);
    printf("\n");
}

void hash_password(const char *pw, const char *algo_name) {
    const EVP_MD *algo = NULL;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char hash[MAX_LEN];
    unsigned int hash_len = 0;

    if (!ctx) {
        printf("Error: failed to create digest context.\n");
        return;
    }

    if (strcmp(algo_name, "md5") == 0) {
        algo = EVP_md5();
    } else if (strcmp(algo_name, "sha256") == 0) {
        algo = EVP_sha256();
    } else if (strcmp(algo_name, "sha512") == 0) {
        algo = EVP_sha512();
    } else {
        printf("Unsupported algorithm: %s\n", algo_name);
        EVP_MD_CTX_free(ctx);
        return;
    }

    if (EVP_DigestInit_ex(ctx, algo, NULL) != 1 ||
        EVP_DigestUpdate(ctx, pw, strlen(pw)) != 1 ||
        EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        printf("Hashing failed.\n");
    } else {
        printf("%s hash: ", algo_name);
        print_hash(hash, hash_len);
    }

    EVP_MD_CTX_free(ctx);
}

void display_menu() {
    printf("\nPassword Tool Menu:\n");
    printf("1. Generate a random password\n");
    printf("2. Hash a password\n");
    printf("3. Exit\n");
    printf("Choose an option: ");
}

int main() {
    int choice;
    char pw[MAX_LEN], algo[16];
    int length;

    srand(time(NULL));

    while (1) {
        display_menu();
        if (scanf("%d", &choice) != 1) {
            printf("Invalid input. Please enter a number.\n");
            while (getchar() != '\n'); 
            continue;
        }

        switch (choice) {
            case 1: 
                printf("Enter the password length (1-%d): ", MAX_LEN - 1);
                if (scanf("%d", &length) != 1 || length < 1 || length >= MAX_LEN) {
                    printf("Invalid length. Please try again.\n");
                    while (getchar() != '\n'); 
                    break;
                }
                generate_password(length);
                break;

            case 2: 
                printf("Enter password to hash: ");
                if (scanf("%255s", pw) != 1) {
                    printf("Invalid password input.\n");
                    while (getchar() != '\n'); 
                    break;
                }
                printf("Choose algorithm (md5/sha256/sha512): ");
                if (scanf("%15s", algo) != 1) {
                    printf("Invalid algorithm input.\n");
                    while (getchar() != '\n'); 
                    break;
                }
                hash_password(pw, algo);
                break;

            case 3: 
                printf("Exiting program...\n");
                return 0;

            default:
                printf("Invalid option. Please try again.\n");
        }
    }

    return 0;
}