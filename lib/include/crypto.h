//
// Created by Dzmitry Valkovich on 8/19/20.
//

#pragma once

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ecdsa.h>
#include <openssl/ec.h>
#include <openssl/conf.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/md5.h>

#include <iostream>
#include <string>

namespace Crypto {
    class ECC {
    public:
        ECC();

        ~ECC();

        int LoadPubkey(const std::string &pubkey);

        int LoadPrivkey(const std::string &privkey);

        int GenerateKeys(const std::string &pubkeyfile, const std::string &privkeyfile, std::string curve_name);

        int Sign(uint8_t *msg, size_t msglen, const std::string &sha_alg);

        uint8_t *GetSignature();

        [[nodiscard]] size_t GetSignatureLen() const;

        std::string DumpSignature();

        void SetSignature(std::string payload);

        int Verify(uint8_t *msg, size_t msglen, uint8_t *signature, size_t signature_len, const std::string &sha_alg);

    private:

        int ToNid(std::string curvename);

        uint8_t signature[256];
        size_t signature_len;

        EC_KEY *publickey;
        EC_KEY *privatekey;
        EVP_PKEY *evp_sign_key;
        EVP_PKEY *evp_verify_key;
    };

}