#include <tfhe/tfhe.h>
#include <iostream>
#include <cryptopp/modes.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>
#include <time.h>
#include "./include/hascompare.h"

class RSAToTFHE
{
private:
    TFheGateBootstrappingCloudKeySet *cloudKey;
    string cloudKeyName;
    string offer;

public:
    LweSample *cipher;

    RSAToTFHE(string AESKeyName, string offer, string cloudKeyName)
    {
        cout << "RTT 1" << endl;
        RSADecryption(AESKeyName);
        cout << "RTT 2" << endl;
        FILE *ck = fopen(cloudKeyName.c_str(), "rb");
        cloudKey = new_tfheGateBootstrappingCloudKeySet_fromFile(ck);
        cipher  = new_gate_bootstrapping_ciphertext_array(16, cloudKey->params);
        cout << &cipher[0] << endl;
        fclose(ck);
        cout << "RTT 3" << endl;
        aes_iv_t iv{};
        aes_key_t AESKey = getAESKey("AES2.key");
        cout << "RTT 4" << endl;
        decrypt(AESKey, iv, offer, "TFHE.offer");
        cout << "RTT 5" << endl;
        getCipher("TFHE.offer");
        cout << "RTT 6" << endl;
    }

    ~RSAToTFHE() {}

    void getCipher(string fileName)
    {
        LweSample *tmp = new_gate_bootstrapping_ciphertext_array(16, cloudKey->params);
        FILE *cloud_data = fopen(fileName.c_str(), "rb");
        for (int i = 0; i < 16; i++)
        {
            cout << i << endl;
            import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &tmp[i], cloudKey->params);
        }
        fclose(cloud_data);
    }

    void decrypt(const aes_key_t &key, const aes_iv_t &iv,
                 const std::string &filename_in, const std::string &filename_out)
    {
        CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption cipher{};
        cipher.SetKeyWithIV(key.data(), key.size(), iv.data());

        std::ifstream in{filename_in, std::ios::binary};
        std::ofstream out{filename_out, std::ios::binary};

        CryptoPP::FileSource{in, /*pumpAll=*/true,
                             new CryptoPP::StreamTransformationFilter{
                                 cipher, new CryptoPP::FileSink{out}}};
    }
    void RSADecryption(string filename)
    {
        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::RSAES_OAEP_SHA_Decryptor dec;
        dec.AccessKey().BERDecode(CryptoPP::FileSource("privateKey.key", true).Ref());

        cout << "[RSATOTFHE][RSADecryption] filename: " << filename << endl;

        // std::ifstream in{"AES.key", std::ios::binary};
        CryptoPP::FileSource ss2(filename.c_str(), true,
                                 new CryptoPP::PK_DecryptorFilter(rng, dec,
                                                                  new CryptoPP::FileSink("AES2.key")) // PK_DecryptorFilter
        );                                                                                            // StringSource
    }
    aes_key_t getAESKey(string filename)
    {
        aes_key_t key;
        CryptoPP::FileSource fs(filename.c_str(), true, new CryptoPP::ArraySink(key.data(), key.size()));
        return key;
    }
};