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
    string fd_data = GetCurrentWorkingDir()+"/"+ get_path("fd_data");

    // GENERATE AES KEY PEER AND CIPHER PRIVATE KEY WITH RSA
    aes_key_t AESkey = utils_generate_cipher_AESKey(fd_data + prefix + "AES.key", RSAfilename);

    // GENERATE IV
    aes_iv_t iv{};
    CryptoPP::AutoSeededRandomPool AESrng{};
    AESrng.GenerateBlock(iv.data(), iv.size());    
    string ivFileName = fd_data + prefix + "newIV.data";
    CryptoPP::ArraySource as(iv.data(), iv.size(), true, new CryptoPP::FileSink(ivFileName.c_str()));

    // CIPHER FHE OFFER WITH AES PUBLIC KEY
    utils_encryptFHEOfferWithAES(AESkey, 
                                 iv, 
                                 fd_data + prefix + "cloud.data", 
                                 fd_data + prefix + "AES.data");
}


void cipherOfferWithFHE(string prefix, string str_value)
{
    //// ROLE:ENDUSER

    int value=atoi(str_value.c_str());

    string FHE_metadata = get_filename("FHE_metadata");
    FILE *params_file = fopen(FHE_metadata.c_str(), "rb");
    TFheGateBootstrappingParameterSet *params = new_tfheGateBootstrappingParameterSet_fromFile(params_file);
    fclose(params_file);

    string FHE_sk = get_filename("FHE_sk");
    FILE *secret_key = fopen(FHE_sk.c_str(), "rb");
    TFheGateBootstrappingSecretKeySet *key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
    fclose(secret_key);

    LweSample *ciphertext1 = new_gate_bootstrapping_ciphertext_array(16, params);
    for (int i = 0; i < 16; i++)
    {
        bootsSymEncrypt(&ciphertext1[i], (value >> i) & 1, key);
    }


    string fd_data = GetCurrentWorkingDir()+"/"+get_path("fd_data");

    string filename = fd_data + prefix + "cloud.data";
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
    string fd_data = GetCurrentWorkingDir()+"/"+get_path("fd_data");
    std::string AESKeyName1 = fd_data+ prefix+"AES.key";
    std::string offerName1 = fd_data+prefix+"AES.data";
    string RSA_pk= get_filename("RSA_pk");

    cipherOfferWithFHE(prefix, offer);  // RETRIEVE FHE DATA AND CIPHER OFFER IN FHE
    addAESLayer(prefix, RSA_pk);             // CIPHER AES KEY IN RSA            
}
