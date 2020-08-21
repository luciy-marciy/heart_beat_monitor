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

        // loads in the pubkey
        int LoadPubkey(std::string pubkey);

        int LoadPrivkey(std::string privkey);

        int GenerateKeys(std::string pubkeyfile, std::string privkeyfile, std::string curve_name);

        int Sign(uint8_t *msg, size_t msglen, std::string sha_alg);

        uint8_t *GetSignature();

        size_t GetSignatureLen();

        int Verify(uint8_t *msg, size_t msglen, uint8_t *signature, size_t signature_len, std::string sha_alg);

        std::string DumpSignature();

        void SetSignature(std::string payload);

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