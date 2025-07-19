#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iomanip>
#include <limits>

class PasswordTool {
public:
    void run() {
        initializeRandomGenerator();

        while (true) {
            displayMenu();
            int choice = getMenuChoice();

            switch (choice) {
                case 1:
                    handlePasswordGeneration();
                    break;
                case 2:
                    handlePasswordHashing();
                    break;
                case 3:
                    std::cout << "Exiting program...\n";
                    return;
                default:
                    std::cout << "Invalid option. Please try again.\n";
            }
        }
    }

private:
    std::mt19937 rng;

    void initializeRandomGenerator() {
        std::random_device rd;
        rng.seed(rd());
    }

    void displayMenu() const {
        std::cout << "\nPassword Tool Menu:\n"
        << "1. Generate a random password\n"
        << "2. Hash a password\n"
        << "3. Exit\n"
        << "Choose an option: ";
    }

    int getMenuChoice() const {
        int choice;
        while (!(std::cin >> choice)) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "Invalid input. Please enter a number: ";
        }
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        return choice;
    }

    void handlePasswordGeneration() {
        constexpr int MAX_LEN = 256;
        std::cout << "Enter the password length (1-" << MAX_LEN - 1 << "): ";

        int length;
        if (!(std::cin >> length) || length < 1 || length >= MAX_LEN) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "Invalid length. Please try again.\n";
            return;
        }

        generatePassword(length);
    }

    void generatePassword(int length) {
        const std::string charset =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        "!@#$^&*()-_=+[]{}";

        std::uniform_int_distribution<size_t> dist(0, charset.size() - 1);
        std::string password;

        for (int i = 0; i < length; ++i) {
            password += charset[dist(rng)];
        }

        std::cout << "Your generated password is: " << password << "\n";
    }

    void handlePasswordHashing() {
        std::cout << "Enter password to hash: ";
        std::string password;
        std::getline(std::cin, password);

        std::cout << "Choose algorithm (md5/sha256/sha512): ";
        std::string algorithm;
        std::getline(std::cin, algorithm);

        hashPassword(password, algorithm);
    }

    void hashPassword(const std::string& password, const std::string& algorithm) {
        const EVP_MD* algo = nullptr;

        if (algorithm == "md5") {
            algo = EVP_md5();
        } else if (algorithm == "sha256") {
            algo = EVP_sha256();
        } else if (algorithm == "sha512") {
            algo = EVP_sha512();
        } else {
            std::cout << "Unsupported algorithm: " << algorithm << "\n";
            return;
        }

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) {
            std::cout << "Error: failed to create digest context.\n";
            return;
        }

        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hashLength = 0;

        if (EVP_DigestInit_ex(ctx, algo, nullptr) != 1 ||
            EVP_DigestUpdate(ctx, password.data(), password.length()) != 1 ||
            EVP_DigestFinal_ex(ctx, hash, &hashLength) != 1) {
            std::cout << "Hashing failed.\n";
            } else {
                std::cout << algorithm << " hash: ";
                printHash(hash, hashLength);
            }

            EVP_MD_CTX_free(ctx);
    }

    void printHash(const unsigned char* hash, unsigned int length) const {
        std::cout << std::hex << std::setfill('0');
        for (unsigned int i = 0; i < length; ++i) {
            std::cout << std::setw(2) << static_cast<int>(hash[i]);
        }
        std::cout << std::dec << "\n";
    }
};

int main() {
    PasswordTool tool;
    tool.run();
    return 0;
}
