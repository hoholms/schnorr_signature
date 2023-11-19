#include "SchnorrSignature.h"
#include <iostream>

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
        std::cerr << "Error generating key pair." << std::endl;
        return nullptr;
    }

    if (!EC_KEY_generate_key(key)) {
        std::cerr << "Error generating key pair." << std::endl;
        EC_KEY_free(key);
        return nullptr;
    }

    keyPair = key;
    return key;
}

ECDSA_SIG *SchnorrSignature::sign(const std::string &message, EC_KEY *privateKey) {
    if (!privateKey) {
        std::cerr << "Private key not provided." << std::endl;
        return nullptr;
    }

    const EC_GROUP *group = EC_KEY_get0_group(privateKey);
    const BIGNUM *privateKeyBN = EC_KEY_get0_private_key(privateKey);

    ECDSA_SIG *signature = ECDSA_do_sign(reinterpret_cast<const unsigned char *>(message.c_str()), message.length(),
                                         privateKey);
    return signature;
}

bool SchnorrSignature::verify(const std::string &message, ECDSA_SIG *signature, EC_KEY *publicKey) {
    if (!signature || !publicKey) {
        std::cerr << "Invalid signature or public key." << std::endl;
        return false;
    }

    int result = ECDSA_do_verify(reinterpret_cast<const unsigned char *>(message.c_str()), message.length(), signature,
                                 publicKey);

    return (result == 1);
}

void SchnorrSignature::printKeyPair() const {
    if (keyPair) {
        std::cout << "Public Key: " << EC_POINT_point2hex(EC_KEY_get0_group(keyPair), EC_KEY_get0_public_key(keyPair),
                                                          POINT_CONVERSION_UNCOMPRESSED, nullptr) << std::endl;
    } else {
        std::cerr << "Key pair is null." << std::endl;
    }
}

void SchnorrSignature::printSignature(ECDSA_SIG *signature) const {
    if (signature) {
        std::cout << "Signature: r = " << BN_bn2hex(ECDSA_SIG_get0_r(signature)) << ", s = "
                  << BN_bn2hex(ECDSA_SIG_get0_s(signature)) << std::endl;
    } else {
        std::cerr << "Signature is null." << std::endl;
    }
}
