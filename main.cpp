#include "SchnorrSignature.h"
#include <iostream>

void printSeparator() {
    std::cout << "--------------------------------------------" << std::endl;
}

int main() {
    SchnorrSignature schnorr;

    // Генерация ключевой пары
    std::cout << "Generating key pair..." << std::endl;
    EC_KEY *keyPair = schnorr.generateKeyPair();
    if (!keyPair) {
        std::cerr << "Error generating key pair." << std::endl;
        return 1;
    }
    std::cout << "Key pair generated successfully." << std::endl;
    printSeparator();

    // Подпись
    std::string message = "Hello, Schnorr!";
    std::cout << "Signing message: " << message << "..." << std::endl;
    ECDSA_SIG *signature = schnorr.sign(message, keyPair);
    if (!signature) {
        std::cerr << "Error creating signature." << std::endl;
        EC_KEY_free(keyPair);
        return 1;
    }
    std::cout << "Message signed successfully." << std::endl;
    printSeparator();

    // Верификация
    std::cout << "Verifying signature..." << std::endl;
    bool verified = schnorr.verify(message, signature, keyPair);
    if (verified) {
        std::cout << "Signature verification: Passed" << std::endl;
    } else {
        std::cerr << "Signature verification: Failed" << std::endl;
    }
    printSeparator();

    // Вывод информации о ключах и подписи
    std::cout << "Key Pair Information:" << std::endl;
    schnorr.printKeyPair();
    printSeparator();

    std::cout << "Signature Information:" << std::endl;
    schnorr.printSignature(signature);
    printSeparator();

    // Очистка ресурсов
    ECDSA_SIG_free(signature);
    EC_KEY_free(keyPair);

    return verified ? 0 : 1;
}
