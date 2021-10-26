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
#include <iostream>
#include <ctime>
#include <iomanip>

using aes_key_t = std::array<byte, CryptoPP::AES::DEFAULT_KEYLENGTH>;
using aes_iv_t = std::array<byte, CryptoPP::AES::BLOCKSIZE>;

namespace std
{
    class Hasher
    {
    private:
        TFheGateBootstrappingParameterSet *params;
        TFheGateBootstrappingSecretKeySet *key;

    public:
        Hasher(int minimum_lambda, uint32_t seed[], string task)
        {    

            if(task == "newProject"){
                cout<<"[HASHER] new project";
            }

            else if(task =="newOffer"){
                cout<<"[HASHER] new offer";

                // LOAD PARAMS AND SECRET KEY
                FILE* params_file = fopen("params.metadata", "rb");
                TFheGateBootstrappingParameterSet* params= new_tfheGateBootstrappingParameterSet_fromFile(params_file);
                fclose(params_file);

                FILE* secret_key = fopen("secret.key","rb");
                TFheGateBootstrappingSecretKeySet* key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
                fclose(secret_key);

            }
            else{
                cout<<"[HASHER] unknown";
            }
            //    params = new_default_gate_bootstrapping_parameters(minimum_lambda);
            //    tfhe_random_generator_setSeed(seed, 3);
            //    key = new_random_gate_bootstrapping_secret_keyset(params);


            //reads the cloud key from file
            //FILE* cloud_key = fopen("cloud.key","rb");
            //TFheGateBootstrappingCloudKeySet* bk = new_tfheGateBootstrappingCloudKeySet_fromFile(cloud_key);
            //fclose(cloud_key);
        
            //the params are inside the key
            //const TFheGateBootstrappingParameterSet* params = bk->params;

            //reads the cloud key from file
            //FILE* secret_key = fopen("secret.key","rb");
            //TFheGateBootstrappingSecretKeySet* key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
            //fclose(secret_key);

            //}
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
        CryptoPP::RSA::PublicKey  generateRSAKey() {
            AutoSeededRandomPool rng;
            InvertibleRSAFunction params;
            params.GenerateRandomWithKeySize(rng, 1024);
            CryptoPP::RSA::PrivateKey privateKey(params);
            CryptoPP::RSA::PublicKey publicKey(params);

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
            CryptoPP::RSA::PublicKey publicKey = generateRSAKey();
            AESrng.GenerateBlock(tmpkey.data(), tmpkey.size());
            CryptoPP::ArraySource as(tmpkey.data(), tmpkey.size(), true, new CryptoPP::FileSink(filename.c_str()));
            RSAEncryption(filename, publicKey, AESrng);
            return tmpkey;
        }

        aes_key_t generateAESKey(string filename, string RSAfilename) {
            //cout <<"generating aes key"<<endl;
            CryptoPP::AutoSeededRandomPool AESrng{};
            aes_key_t tmpkey{};
            CryptoPP::RSA::PublicKey publicKey;

            FileSource input(RSAfilename.c_str(), true);
            publicKey.BERDecode(input); // 
            AESrng.GenerateBlock(tmpkey.data(), tmpkey.size());
            //std::cout << "fileSink filename: "<< filename.c_str();
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
        {   //export the TFHE secret key to file for later use
            FILE *secret_key = fopen("secret.key", "wb");
            export_tfheGateBootstrappingSecretKeySet_toFile(secret_key, this->key);
            fclose(secret_key);
        }
        void exportCloudKey()
        {
            //export the TFHE cloud key to file for later use
            FILE *cloud_key = fopen("cloud.key", "wb");
            auto tmp = &key->cloud;
            export_tfheGateBootstrappingCloudKeySet_toFile(cloud_key, tmp);
            fclose(cloud_key);
        }

        void exportParams()
        {
            //export the TFHE params to file for later use
            FILE *params_file = fopen("params.metadata", "wb");
            auto tmp = &key->cloud;
            export_tfheGateBootstrappingCloudKeySet_toFile(params_file, tmp);
            fclose(params_file);
        }

        void exportData(LweSample *ciphertext)
        {
            FILE *cloud_data = fopen("cloud.data", "wb");
            for (size_t i = 0; i < 16; i++)
            {
                export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext[i], params);
            }
            fclose(cloud_data);

        }

        void export2Data(std::vector<LweSample *> ciphertext, std::string filename)
        {
            FILE *cloud_data = fopen(filename.c_str(), "wb");
            for (size_t j = 0; j < ciphertext.size(); j++)
            {
                for (int i = 0; i < 16; i++)
                    export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext[j][i], params);
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

        string RSAEncryption(string filename, CryptoPP::RSA::PublicKey publicKey, AutoSeededRandomPool &rng)
        {
            //cout<<"i am rsa encryption"<<endl;
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

            return "1";
        }
    };
    } // namespace std