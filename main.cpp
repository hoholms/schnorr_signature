#include "SchnorrSignature.h"
#include <iostream>

using namespace std;

void printSeparator() {
    cout << "--------------------------------------------" << endl;
}

int main() {
    SchnorrSignature schnorr;

    // Генерация ключевой пары
    cout << "Generating key pair..." << endl;
    EC_KEY *keyPair = schnorr.generateKeyPair();
    if (!keyPair) {
        cerr << "Error generating key pair." << endl;
        return 1;
    }
    cout << "Key pair generated successfully." << endl;
    printSeparator();

    // Подпись
    string message = "Hello, Schnorr!";
    cout << "Signing message: " << message << "..." << endl;
    ECDSA_SIG *signature = schnorr.sign(message, keyPair);
    if (!signature) {
        cerr << "Error creating signature." << endl;
        EC_KEY_free(keyPair);
        return 1;
    }
    cout << "Message signed successfully." << endl;
    printSeparator();

    // Верификация
    cout << "Verifying signature..." << endl;
    bool verified = schnorr.verify(message, signature, keyPair);
    if (verified) {
        cout << "Signature verification: Passed" << endl;
    } else {
        cerr << "Signature verification: Failed" << endl;
    }
    printSeparator();

    // Вывод информации о ключах и подписи
    cout << "Key Pair Information:" << endl;
    schnorr.printKeyPair();
    printSeparator();

    cout << "Signature Information:" << endl;
    schnorr.printSignature(signature);
    printSeparator();

    return verified ? 0 : 1;
}
