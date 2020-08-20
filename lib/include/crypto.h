//
// Created by Dzmitry Valkovich on 8/19/20.
//

#pragma once

#include <iostream>
#include <string>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ecdsa.h>
#include <openssl/ec.h>
#include <openssl/conf.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
//#include <stdio.h>
//#include <string.h>
//#include <stdint.h>

namespace Crypto {
    class ECC {
    public:
        ECC() {
            evp_sign_key = nullptr;
            evp_verify_key = nullptr;

            signature_len = sizeof(signature);

            ERR_load_crypto_strings();
            OpenSSL_add_all_algorithms();
            OPENSSL_config(NULL);
            RAND_poll();
        }

        ~ECC() {
            if (evp_sign_key)
                EVP_PKEY_free(evp_sign_key);
            if (evp_verify_key)
                EVP_PKEY_free(evp_verify_key);

            EVP_cleanup();
            CRYPTO_cleanup_all_ex_data();
            ERR_free_strings();
        }

        // loads in the pubkey
        int LoadPubkey(std::string pubkey) {
            FILE *fp;

            // load in the keys
            fp = fopen(pubkey.c_str(), "r");
            if (!fp) {
                return -1;
            }

            publickey = PEM_read_EC_PUBKEY(fp, NULL, NULL, NULL);
            if (!publickey) {
                ERR_print_errors_fp(stderr);
                return -1;
            }

            evp_verify_key = EVP_PKEY_new();

            int ret;

            ret = EVP_PKEY_assign_EC_KEY(evp_verify_key, publickey);
            if (ret != 1) {
                ERR_print_errors_fp(stderr);
                return -1;
            }

            fclose(fp);

            std::cout << "pubkey load ok" << std::endl;

            return 0;
        }

        int LoadPrivkey(std::string privkey) {
            FILE *fp;

            fp = fopen(privkey.c_str(), "r");
            if (!fp) {
                return -1;
            }

            privatekey = PEM_read_ECPrivateKey(fp, NULL, NULL, NULL);
            if (!privatekey) {
                ERR_print_errors_fp(stderr);
                return -1;
            }

            // validate the key
            EC_KEY_check_key(privatekey);

            evp_sign_key = EVP_PKEY_new();

            int ret;

            ret = EVP_PKEY_assign_EC_KEY(evp_sign_key, privatekey);
            if (ret != 1) {
                ERR_print_errors_fp(stderr);
                return -1;
            }

            fclose(fp);
            return 0;
        }

        int GenerateKeys(std::string pubkeyfile, std::string privkeyfile, std::string curve_name) {
            EC_KEY *keygen;
            int nid = ToNid(curve_name);

            if (nid == -1) {
                return -1;
            }

            // get curve name
            keygen = EC_KEY_new_by_curve_name(nid);
            if (!keygen) {
                ERR_print_errors_fp(stderr);
                return -1;
            }

            int ret;

            // run the key generation .. we aren't doing the curve parameters
            ret = EC_KEY_generate_key(keygen);
            if (ret != 1) {
                ERR_print_errors_fp(stderr);
                return -1;
            }

            ret = EC_KEY_check_key(keygen);
            if (ret != 1) {
                ERR_print_errors_fp(stderr);
                return -1;
            }


            // wirte the keys
            FILE *fp;

            fp = fopen(pubkeyfile.c_str(), "w");
            if (!fp) {
                return -1;
            }

            PEM_write_EC_PUBKEY(fp, keygen);

            fclose(fp);

            fp = fopen(privkeyfile.c_str(), "w");
            if (!fp) {
                return -1;
            }

            PEM_write_ECPrivateKey(fp, keygen, NULL, NULL, 0, NULL, NULL);

            fclose(fp);

            EC_KEY_free(keygen);

            std::cout << "keygen success" << std::endl;
            return 0;
        }

        int Sign(uint8_t *msg, size_t msglen, std::string sha_alg) {
            if (!evp_sign_key || !privatekey) {
                std::cerr << "invalid sign key or private key is not loaded" << std::endl;
                return -1;
            }

            const EVP_MD *md;

            // mark the sha alg to use
            if (sha_alg == "sha256") {
                md = EVP_sha256();
            } else if (sha_alg == "sha1") {
                md = EVP_sha1();
            } else {
                return -1;
            }

            int ret;

            EVP_MD_CTX *mdctx = EVP_MD_CTX_create();

            ret = EVP_DigestSignInit(mdctx, NULL, md, NULL, evp_sign_key);
            if (ret != 1) {
                ERR_print_errors_fp(stderr);
                return -1;
            }

            ret = EVP_DigestSignUpdate(mdctx, msg, msglen);
            if (ret != 1) {
                ERR_print_errors_fp(stderr);
                return -1;
            }

            ret = EVP_DigestSignFinal(mdctx, signature, &signature_len);
            if (ret != 1) {
                ERR_print_errors_fp(stderr);
                return -1;
            }

            EVP_MD_CTX_destroy(mdctx);

            return 0;
        }

        uint8_t *GetSignature() {
            return signature;
        }

        size_t GetSignatureLen() {
            return signature_len;
        }

        int Verify(uint8_t *msg, size_t msglen, uint8_t *signature, size_t signature_len, std::string sha_alg) {
            if (!msg || !signature) {
                std::cerr << "invalid msg or signature" << std::endl;
                return -1;
            }

            const EVP_MD *md;

            if (sha_alg == "sha256") {
                md = EVP_sha256();
            } else if (sha_alg == "sha1") {
                md = EVP_sha1();
            } else {
                return -1;
            }

            int ret;

            EVP_MD_CTX *mdctx = EVP_MD_CTX_create();

            ret = EVP_DigestVerifyInit(mdctx, NULL, md, NULL, evp_verify_key);
            if (ret != 1) {
                ERR_print_errors_fp(stderr);
                return -1;
            }

            ret = EVP_DigestVerifyUpdate(mdctx, msg, msglen);
            if (ret != 1) {
                ERR_print_errors_fp(stderr);
                return -1;
            }

            ret = EVP_DigestVerifyFinal(mdctx, signature, signature_len);
            if (ret != 1) {
                ERR_print_errors_fp(stderr);
                return -1;
            }

            EVP_MD_CTX_destroy(mdctx);

            std::cout << "verify ok" << std::endl;

            return 0;
        }

        std::string DumpSignature() {
            std::string ret;
            size_t i;

            for (i = 0; i < signature_len; ++i) {
                if (i != 0) {
                    ret += ':';
                }

                ret += std::to_string(signature[i]);
            }
            return ret += ':';
        }

        void SetSignature(std::string payload) {
            std::string delimiter = ":";
            size_t pos = 0, array_pos = 0;
            std::string token;
            while ((pos = payload.find(delimiter)) != std::string::npos) {
                token = payload.substr(0, pos);
                this->signature[array_pos] = std::stoi(token);
                payload.erase(0, pos + delimiter.length());
                ++array_pos;
            }

            this->signature_len = array_pos;
        }

    private:

        int ToNid(std::string curvename) {
            if (curvename == "secp256k1") {
                return NID_secp256k1;
            } else if (curvename == "brainpool256r1") {
                return NID_brainpoolP256r1;
            }

            return -1;
        }

        uint8_t signature[256];
        size_t signature_len;

        EC_KEY *publickey;
        EC_KEY *privatekey;
        EVP_PKEY *evp_sign_key;
        EVP_PKEY *evp_verify_key;
    };

}