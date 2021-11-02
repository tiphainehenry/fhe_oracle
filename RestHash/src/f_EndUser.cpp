#include <boost/algorithm/string.hpp>
#include <cryptopp/modes.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>
#include <cryptopp/aes.h>
#include <cryptopp/rsa.h>
#include <cryptopp/filters.h>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <ipfs/client.h>
#include <nlohmann/json.hpp>
#include <sstream>
#include <stdexcept>
#include <stdio.h>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>

#include "../include/handler.h"


using namespace CryptoPP;
using namespace std;

using aes_key_t = std::array<byte, CryptoPP::AES::DEFAULT_KEYLENGTH>;
using aes_iv_t = std::array<byte, CryptoPP::AES::BLOCKSIZE>;

void utils_RSAEncryption(string filename, CryptoPP::RSA::PublicKey publicKey, AutoSeededRandomPool &rng)
{
    /// ROLE: ENDUSER
    string plain, cipher, tmp;
    ifstream MyReadFile(filename);

    while (getline(MyReadFile, tmp))
        plain += tmp;
    MyReadFile.close();
    RSAES_OAEP_SHA_Encryptor e(publicKey);
    StringSource ss1(plain, true, new PK_EncryptorFilter(rng, e, new StringSink(cipher)));
    ofstream MyFile(filename, ofstream::out | ofstream::trunc);
    MyFile << cipher;
    MyFile.close();
}

aes_key_t utils_generate_cipher_AESKey(string AESfilename, string RSAfilename)
{
    /// ROLE: ENDUSER
    CryptoPP::AutoSeededRandomPool AESrng{};
    aes_key_t tmpkey{};
    CryptoPP::RSA::PublicKey RSApublicKey;

    // generate AES KEY and store it
    AESrng.GenerateBlock(tmpkey.data(), tmpkey.size());
    CryptoPP::ArraySource as(tmpkey.data(), tmpkey.size(), true, new CryptoPP::FileSink(AESfilename.c_str()));

    // fetch RSA public key
    FileSource input(RSAfilename.c_str(), true);
    RSApublicKey.BERDecode(input);

    // encrypt AES public key with RSA
    utils_RSAEncryption(AESfilename, RSApublicKey, AESrng);
    return tmpkey;
}

void utils_encryptFHEOfferWithAES(const aes_key_t &key, const aes_iv_t &iv,
                                  const std::string &filename_in, const std::string &filename_out)
{
    //// ROLE:ENDUSER

    CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption cipher{};
    cipher.SetKeyWithIV(key.data(), key.size(), iv.data());

    std::ifstream in{filename_in, std::ios::binary};
    std::ofstream out{filename_out, std::ios::binary};

    CryptoPP::FileSource{in, true,
                         new CryptoPP::StreamTransformationFilter{
                             cipher, new CryptoPP::FileSink{out}}};
}

LweSample *utils_cipherInt(int message, TFheGateBootstrappingParameterSet *params, TFheGateBootstrappingSecretKeySet *key)
{
    /// ROLE: ENDUSER
    LweSample *cipherText = new_gate_bootstrapping_ciphertext_array(16, params);
    for (size_t i = 0; i < 16; i++)
    {
        bootsSymEncrypt(&cipherText[i], (message >> i) & 1, key);
    }
    return (cipherText);
}


void addAESLayer(std::string prefix, std::string RSAfilename)
{
    //// ROLE:ENDUSER

    // GENERATE AES KEY PEER AND CIPHER PRIVATE KEY WITH RSA
    aes_key_t AESkey = utils_generate_cipher_AESKey(".tmp/" + prefix + "AES.key", RSAfilename);

    // GENERATE IV
    aes_iv_t iv{};
    CryptoPP::AutoSeededRandomPool AESrng{};
    AESrng.GenerateBlock(iv.data(), iv.size());
    string ivFileName = ".tmp/" + prefix + "newIV.data";
    CryptoPP::ArraySource as(iv.data(), iv.size(), true, new CryptoPP::FileSink(ivFileName.c_str()));

    // CIPHER FHE OFFER WITH AES PUBLIC KEY
    utils_encryptFHEOfferWithAES(AESkey, iv, ".tmp/" + prefix + "cloud.data", ".tmp/" + prefix + "AES.data");
}


void cipherOfferWithFHE(string prefix, string str_value)
{
    //// ROLE:ENDUSER

    int value=atoi(str_value.c_str());

    FILE *params_file = fopen(".tmp/params.metadata", "rb");
    TFheGateBootstrappingParameterSet *params = new_tfheGateBootstrappingParameterSet_fromFile(params_file);
    fclose(params_file);

    FILE *secret_key = fopen(".tmp/secret.key", "rb");
    TFheGateBootstrappingSecretKeySet *key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
    fclose(secret_key);

    LweSample *ciphertext1 = new_gate_bootstrapping_ciphertext_array(16, params);
    for (int i = 0; i < 16; i++)
    {
        bootsSymEncrypt(&ciphertext1[i], (value >> i) & 1, key);
    }

    string filename = ".tmp/" + prefix + "cloud.data";
    FILE *cloud_data = fopen(filename.c_str(), "wb");
    for (int i = 0; i < 16; i++)
        export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext1[i], params);
    fclose(cloud_data);

    //clean up all pointers
    delete_gate_bootstrapping_ciphertext_array(16, ciphertext1); //...
    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);
}

void registerMyOffer(string offer, string prefix){
    //// ROLE:ENDUSER

    string RSAfilename=".tmp/publicKey.key";

    std::string AESKeyName1 = ".tmp/"+ prefix+"AES.key";
    std::string offerName1 = ".tmp/"+prefix+"AES.data";

    cipherOfferWithFHE(prefix, offer);  // RETRIEVE FHE DATA AND CIPHER OFFER IN FHE
    addAESLayer(prefix, RSAfilename);             // CIPHER AES KEY IN RSA            
}
