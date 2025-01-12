#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <string>
#include <vector>
#include <algorithm>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define KEY_SIZE 32
#define IV_SIZE 16
#define ENCRYPTED_PASS_SIZE 128

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

class PasswordManager {
private:
    std::string keyFile = "key.bin";
    std::string passwordFile = "passwords.txt";
    unsigned char key[KEY_SIZE];

    void initializeKey() {
        if (!std::ifstream(keyFile)) {
            generateKey();
        }
        loadKey();
    }

    void generateKey() {
        if (!RAND_bytes(key, KEY_SIZE)) {
            handleErrors();
        }
        std::ofstream file(keyFile, std::ios::binary);
        file.write(reinterpret_cast<const char*>(key), KEY_SIZE);
        std::cout << "New encryption key generated and saved." << std::endl;
    }

    void loadKey() {
        std::ifstream file(keyFile, std::ios::binary);
        if (file.read(reinterpret_cast<char*>(key), KEY_SIZE)) {
            std::cout << "Encryption key loaded." << std::endl;
        } else {
            handleErrors();
        }
    }

    std::string encrypt(const std::string& plaintext) {
        unsigned char iv[IV_SIZE];
        if (!RAND_bytes(iv, IV_SIZE)) {
            handleErrors();
        }

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            handleErrors();
        }

        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
            handleErrors();
        }

        std::vector<unsigned char> ciphertext(ENCRYPTED_PASS_SIZE);
        int len;
        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.size()) != 1) {
            handleErrors();
        }

        int finalLen;
        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &finalLen) != 1) {
            handleErrors();
        }
        EVP_CIPHER_CTX_free(ctx);

        std::ostringstream oss;
        oss << std::hex;
        for (size_t i = 0; i < IV_SIZE; i++) {
            oss << std::setw(2) << std::setfill('0') << static_cast<int>(iv[i]);
        }
        for (size_t i = 0; i < len + finalLen; i++) {
            oss << std::setw(2) << std::setfill('0') << static_cast<int>(ciphertext[i]);
        }

        return oss.str();
    }

    std::string decrypt(const std::string& hexCiphertext) {
        unsigned char iv[IV_SIZE];
        for (size_t i = 0; i < IV_SIZE; i++) {
            iv[i] = std::stoi(hexCiphertext.substr(i * 2, 2), nullptr, 16);
        }

        size_t ciphertextLen = (hexCiphertext.size() / 2) - IV_SIZE;
        std::vector<unsigned char> ciphertext(ciphertextLen);
        for (size_t i = 0; i < ciphertextLen; i++) {
            ciphertext[i] = std::stoi(hexCiphertext.substr((IV_SIZE + i) * 2, 2), nullptr, 16);
        }

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            handleErrors();
        }

        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
            handleErrors();
        }

        std::vector<unsigned char> plaintext(ENCRYPTED_PASS_SIZE);
        int len;
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1) {
            handleErrors();
        }

        int finalLen;
        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &finalLen) != 1) {
            handleErrors();
        }
        EVP_CIPHER_CTX_free(ctx);

        return std::string(plaintext.begin(), plaintext.begin() + len + finalLen);
    }

    void displayTable(const std::vector<std::pair<std::string, std::string>>& data) {
        std::cout << "\n+-------------------+-------------------+\n";
        std::cout << "| Username          | Password          |\n";
        std::cout << "+-------------------+-------------------+\n";
        for (const auto& [username, password] : data) {
            std::cout << "| " << std::setw(17) << std::left << username
                      << " | " << std::setw(17) << std::left << password << " |\n";
        }
        std::cout << "+-------------------+-------------------+\n";
    }

public:
    PasswordManager() {
        initializeKey();
    }

    void viewPasswords() {
        std::ifstream file(passwordFile);
        if (!file) {
            std::cout << "No passwords saved yet. Add some passwords first.\n";
            return;
        }

        std::vector<std::pair<std::string, std::string>> passwords;
        std::string line;
        while (std::getline(file, line)) {
            std::istringstream iss(line);
            std::string username, encryptedPassword;
            if (std::getline(iss, username, '|') && std::getline(iss, encryptedPassword)) {
                passwords.emplace_back(username, decrypt(encryptedPassword));
            }
        }

        if (passwords.empty()) {
            std::cout << "No passwords saved yet. Add some passwords first.\n";
            return;
        }

        displayTable(passwords);
    }

    void addPassword() {
        std::string username, password;
        std::cout << "Enter username: ";
        std::getline(std::cin, username);
        std::cout << "Enter password: ";
        std::getline(std::cin, password);

        if (username.empty() || password.empty()) {
            std::cout << "Please enter a valid username and password.\n";
            return;
        }

        std::ofstream file(passwordFile, std::ios::app);
        if (!file) {
            std::cout << "Failed to save password.\n";
            return;
        }

        file << username << "|" << encrypt(password) << "\n";
        std::cout << "Password for account '" << username << "' has been saved securely.\n";
    }

    void run() {
        std::cout << "==========================================\n";
        std::cout << " Welcome to the Secure Password Manager! \n";
        std::cout << "==========================================\n";

        while (true) {
            std::cout << "\nOptions: [view] View passwords | [add] Add passwords | [q] Quit\n";
            std::cout << "Select an option: ";
            std::string mode;
            std::getline(std::cin, mode);
            std::transform(mode.begin(), mode.end(), mode.begin(), ::tolower);

            if (mode == "q") {
                std::cout << "\nThank you for using the Secure Password Manager. Goodbye!\n";
                break;
            } else if (mode == "view") {
                viewPasswords();
            } else if (mode == "add") {
                addPassword();
            } else {
                std::cout << "Invalid option. Please try again.\n";
            }
        }
    }
};

int main() {
    PasswordManager manager;
    manager.run();
    return 0;
}
