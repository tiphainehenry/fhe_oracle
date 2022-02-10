#ifndef HASHER_H
#define HASHER_H
#include <iostream>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <fstream>
#include <cryptopp/modes.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>
#include <cryptopp/aes.h>
#include <cryptopp/rsa.h>
#include <cryptopp/filters.h>
using namespace CryptoPP;
using namespace std;
#include <stdio.h>
#include <ctime>
#include <iomanip>

#include "../Hasher.cc"

using aes_key_t = std::array<byte, CryptoPP::AES::DEFAULT_KEYLENGTH>;
using aes_iv_t = std::array<byte, CryptoPP::AES::BLOCKSIZE>;

namespace std{
class hasher
{
    public:
        Hasher(std::int minimum_lambda, uint32_t seed[]);
        virtual ~Hasher();

        CryptoPP::RSA::PublicKey  generateRSAKey();
        aes_key_t generateAESKey(string filename);
        aes_key_t generateAESKey(string filename, string RSAfilename);

        LweSample *cipherInt(int message);

        void exportKey();
        void exportCloudKey();
        void exportData(LweSample *ciphertext);
        void export2Data(std::vector<LweSample *> ciphertext1, std::string filename);
        void encrypt(const aes_key_t &key, const aes_iv_t &iv,
                    const std::string &filename_in, const std::string &filename_out);

        string RSAEncryption(string filename, CryptoPP::RSA::PublicKey publicKey, AutoSeededRandomPool &rng);

    protected:

    private:
        TFheGateBootstrappingParameterSet *params;
        TFheGateBootstrappingSecretKeySet *key;
};
}

#endif // HASHER_H


