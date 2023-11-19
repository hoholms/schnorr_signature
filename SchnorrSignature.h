#ifndef SCHNORR_SIGNATURE_H
#define SCHNORR_SIGNATURE_H

#include <string>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>

class SchnorrSignature {
public:
    SchnorrSignature();

    ~SchnorrSignature();

    EC_KEY *generateKeyPair();

    ECDSA_SIG *sign(const std::string &message, EC_KEY *privateKey);

    bool verify(const std::string &message, ECDSA_SIG *signature, EC_KEY *publicKey);

    void printKeyPair() const;

    void printSignature(ECDSA_SIG *signature) const;

private:
    EC_KEY *keyPair;
};

#endif // SCHNORR_SIGNATURE_H
