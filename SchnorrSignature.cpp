#include "SchnorrSignature.h"
#include <iostream>

using namespace std;

SchnorrSignature::SchnorrSignature() {
    keyPair = nullptr;
}

SchnorrSignature::~SchnorrSignature() {
    if (keyPair != nullptr) {
        EC_KEY_free(keyPair);
    }
}

EC_KEY *SchnorrSignature::generateKeyPair() {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!key) {
        cerr << "Error generating key pair." << endl;
        return nullptr;
    }

    if (!EC_KEY_generate_key(key)) {
        cerr << "Error generating key pair." << endl;
        EC_KEY_free(key);
        return nullptr;
    }

    keyPair = key;
    return key;
}

ECDSA_SIG *SchnorrSignature::sign(const string &message, EC_KEY *privateKey) {
    if (!privateKey) {
        cerr << "Private key not provided." << endl;
        return nullptr;
    }

    const EC_GROUP *group = EC_KEY_get0_group(privateKey);
    const BIGNUM *privateKeyBN = EC_KEY_get0_private_key(privateKey);

    ECDSA_SIG *signature = ECDSA_do_sign(reinterpret_cast<const unsigned char *>(message.c_str()), message.length(),
                                         privateKey);
    return signature;
}

bool SchnorrSignature::verify(const string &message, ECDSA_SIG *signature, EC_KEY *publicKey) {
    if (!signature || !publicKey) {
        cerr << "Invalid signature or public key." << endl;
        return false;
    }

    int result = ECDSA_do_verify(reinterpret_cast<const unsigned char *>(message.c_str()), message.length(), signature,
                                 publicKey);

    return (result == 1);
}

void SchnorrSignature::printKeyPair() const {
    if (keyPair) {
        cout << "Public Key: " << EC_POINT_point2hex(EC_KEY_get0_group(keyPair), EC_KEY_get0_public_key(keyPair),
                                                          POINT_CONVERSION_UNCOMPRESSED, nullptr) << endl;
    } else {
        cerr << "Key pair is null." << endl;
    }
}

void SchnorrSignature::printSignature(ECDSA_SIG *signature) const {
    if (signature) {
        cout << "r = " << BN_bn2hex(ECDSA_SIG_get0_r(signature)) << "\ns = "
                  << BN_bn2hex(ECDSA_SIG_get0_s(signature)) << endl;
    } else {
        cerr << "Signature is null." << endl;
    }
}
