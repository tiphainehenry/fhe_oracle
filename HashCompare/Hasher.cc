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
using aes_key_t = std::array<byte, CryptoPP::AES::DEFAULT_KEYLENGTH>;
using aes_iv_t = std::array<byte, CryptoPP::AES::BLOCKSIZE>;

class Hasher
{
private:
    TFheGateBootstrappingParameterSet *params;
    TFheGateBootstrappingSecretKeySet *key;

public:
    Hasher(int minimum_lambda, uint32_t seed[])
    {
        params = new_default_gate_bootstrapping_parameters(minimum_lambda);
        tfhe_random_generator_setSeed(seed, 3);
        key = new_random_gate_bootstrapping_secret_keyset(params);
    }
    ~Hasher()
    {
        delete_gate_bootstrapping_secret_keyset(key);
        delete_gate_bootstrapping_parameters(params);
    }
    /**
     * Generate both private and public key in publicKey.key and privateKey.key
     * @return {RSA::PublicKey} publicKey
     * */
    RSA::PublicKey  generateRSAKey() {
        AutoSeededRandomPool rng;
        InvertibleRSAFunction params;
        params.GenerateRandomWithKeySize(rng, 1024);
        RSA::PrivateKey privateKey(params);
        RSA::PublicKey publicKey(params);

        publicKey.DEREncode(FileSink("publicKey.key", true).Ref());
        privateKey.DEREncode(FileSink("privateKey.key", true).Ref());
        return publicKey;
    }
    /***
     * Generate a AES Key and then encrypt it with  RSA method and save it
     * @param {string} location of saved key
     * @return {aes_key_t} uncrypted AES key
     * */ 
    aes_key_t generateAESKey(string filename)
    {
        CryptoPP::AutoSeededRandomPool AESrng{};
        aes_key_t tmpkey{};
        RSA::PublicKey publicKey = generateRSAKey();
        AESrng.GenerateBlock(tmpkey.data(), tmpkey.size());
        CryptoPP::ArraySource as(tmpkey.data(), tmpkey.size(), true, new CryptoPP::FileSink(filename.c_str()));
        RSAEncryption(filename, publicKey, AESrng);
        return tmpkey;
    }

    aes_key_t generateAESKey(string filename, string RSAfilename) {
        CryptoPP::AutoSeededRandomPool AESrng{};
        aes_key_t tmpkey{};
        RSA::PublicKey publicKey;

        FileSource input(RSAfilename.c_str(), true);
        publicKey.BERDecode(input);
        AESrng.GenerateBlock(tmpkey.data(), tmpkey.size());
        CryptoPP::ArraySource as(tmpkey.data(), tmpkey.size(), true, new CryptoPP::FileSink(filename.c_str()));
        RSAEncryption(filename, publicKey, AESrng);
        return tmpkey;
    }

    LweSample *cipherInt(int message)
    {
        LweSample *cipherText = new_gate_bootstrapping_ciphertext_array(16, params);
        for (size_t i = 0; i < 16; i++)
        {
            bootsSymEncrypt(&cipherText[i], (message >> i) & 1, this->key);
        }
        return (cipherText);
    }

    void exportKey()
    {
        FILE *secret_key = fopen("secret.key", "wb");
        export_tfheGateBootstrappingSecretKeySet_toFile(secret_key, this->key);
        fclose(secret_key);
    }
    void exportCloudKey()
    {
        FILE *cloud_key = fopen("cloud.key", "wb");
        auto tmp = &key->cloud;
        export_tfheGateBootstrappingCloudKeySet_toFile(cloud_key, tmp);
        fclose(cloud_key);
    }

    void exportData(LweSample *ciphertext)
    {
        FILE *cloud_data = fopen("cloud.data", "wb");
        for (size_t i = 0; i < 16; i++)
        {
            export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext[i], params);
        }
    }

    void export2Data(std::vector<LweSample *> ciphertext1, std::string filename)
    {
        FILE *cloud_data = fopen(filename.c_str(), "wb");
        for (size_t j = 0; j < ciphertext1.size(); j++)
        {
            for (int i = 0; i < 16; i++)
                export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext1[j][i], params);
        }
        fclose(cloud_data);
    }

    void encrypt(const aes_key_t &key, const aes_iv_t &iv,
                 const std::string &filename_in, const std::string &filename_out)
    {
        CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption cipher{};
        cipher.SetKeyWithIV(key.data(), key.size(), iv.data());

        std::ifstream in{filename_in, std::ios::binary};
        std::ofstream out{filename_out, std::ios::binary};

        CryptoPP::FileSource{in, true,
                             new CryptoPP::StreamTransformationFilter{
                                 cipher, new CryptoPP::FileSink{out}}};
    }

    void RSAEncryption(string filename, RSA::PublicKey publicKey, AutoSeededRandomPool &rng)
    {
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
};