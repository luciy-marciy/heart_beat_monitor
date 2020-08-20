#include <iostream>
#include <string>


#include <crypto.h>

using namespace Crypto;

int main() {
    ECC ec;
    int ret;

    std::string msg = "try this to sign for ec ";
    std::string curvename = "brainpool256r1";
    std::string pubkey = "./ec_brainpool_256r1.pub";
    std::string pkey = "./ec_brainpool_256r1.pkey";

    ret = ec.GenerateKeys(pubkey.c_str(), pkey.c_str(), curvename.c_str());
    if (ret != 0) {
        std::cerr << "failure generating keys" << std::endl;
        return -1;
    }

    ret = ec.LoadPubkey(pubkey.c_str());
    if (ret != 0) {
        std::cerr << "pubkey didn't load " << std::endl;
        return -1;
    }

    ret = ec.LoadPrivkey(pkey.c_str());
    if (ret != 0) {
        std::cerr << "privkey didn't load" << std::endl;
        return -1;
    }

    ret = ec.Sign((uint8_t *) (msg.c_str()), msg.length(), "sha256");
    if (ret != 0) {
        std::cerr << "failure to sign message" << std::endl;
        return -1;
    }

    auto temp = ec.DumpSignature();
    ec.SetSignature(temp);


    ret = ec.Verify((uint8_t *) (msg.c_str()), msg.length(), ec.GetSignature(), ec.GetSignatureLen(), "sha256");
    if (ret != 0) {
        std::cerr << "failed to verify message" << std::endl;
        return -1;
    }

    return 0;
}