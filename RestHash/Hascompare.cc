#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>
#include <iostream>
#include <ctime>
#include <iomanip>
#include "include/hascompare.h"
#include <cryptopp/modes.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/rsa.h>
#include <boost/algorithm/string.hpp>

// #include "./Verif.cc"
// #include "./Hasher.cc"
#include "./Cloud.cc"
#include "./RSAToTFHE.cc"

using namespace CryptoPP;
using aes_key_t = std::array<byte, CryptoPP::AES::DEFAULT_KEYLENGTH>;
using aes_iv_t = std::array<byte, CryptoPP::AES::BLOCKSIZE>;


void provider(int nbr_offers, char *av[])
{
    aes_iv_t iv{};
    CryptoPP::AutoSeededRandomPool AESrng{};
    AESrng.GenerateBlock(iv.data(), iv.size());
    CryptoPP::ArraySource as(iv.data(), iv.size(), true, new CryptoPP::FileSink("newIV.data"));

    uint32_t seed[] = {314, 1592, 657};
    Hasher hasher = Hasher(100, seed,"provider");
    std::vector<LweSample *> cipher;
    for (size_t i = 1; i < nbr_offers; i++)
    {
        cipher.push_back(hasher.cipherInt(atoi(av[i])));
    }

    hasher.exportKey();
    hasher.exportCloudKey();
    hasher.export2Data(cipher, "cloud.data");
    aes_key_t key = hasher.generateAESKey("AES.key");
    hasher.encrypt(key, iv, "cloud.data", "AES.data");
}


/***
 * Create a new offer file and AES key
 * The Key is directly encrypted with "./publicKey.key"
 * 
 * */
void new_offer(int value, string RSAfilename, string prefix)
{
    cout<<"[new offer] 1";

    aes_iv_t iv{};
    CryptoPP::AutoSeededRandomPool AESrng{};
    AESrng.GenerateBlock(iv.data(), iv.size());
    CryptoPP::ArraySource as(iv.data(), iv.size(), true, new CryptoPP::FileSink("newIV.data"));

    cout<<"[new offer] 2";

    uint32_t seed[] = {314, 1592, 657};
    Hasher hasher = Hasher(100, seed, "newOffer"); // to do: modify hasher, create params and store at init of new project
    std::vector<LweSample *> cipher;
    cipher.push_back(hasher.cipherInt(value));

    //hasher.exportKey(); // EXPORT TFHE secret KEY
    //hasher.exportCloudKey(); // EXPORT TFHE public KEY

    cout<<"[new offer] 3";
    hasher.export2Data(cipher, prefix+"cloud.data"); // EXPORT OFFER CIPHERED WITH TFHE

    aes_key_t key = hasher.generateAESKey(prefix+"AES.key", RSAfilename); // GENERATE AES KEY AND CIPHER IT WITH RSA
    hasher.encrypt(key, iv, prefix+"cloud.data", prefix+"AES.data"); 

    cipher.clear(); // RELEASE VECTOR

}

/***
 * Create all the key necessary to the creation of offers
 * 
 * ***/
void new_project()
{
    uint32_t seed[] = {314, 1592, 657};
    const int minimum_lambda = 100;


                cout<<"[HASHER] new project";

                //generate a keyset
                //**************//
                //STEP 1:GENERATE AND STORE PARAMS
                
                //generate params
                TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(minimum_lambda);
                // export the parameter to file for later use
                FILE* params_file = fopen("params.metadata","wb");
                export_tfheGateBootstrappingParameterSet_toFile(params_file, params);
                fclose(params_file);

                //**************//
                //STEP 2: GENERATE AND STORE FHE KEYSET
                //generate a random key
                tfhe_random_generator_setSeed(seed,3);
                TFheGateBootstrappingSecretKeySet* key = new_random_gate_bootstrapping_secret_keyset(params);

                //export the secret key to file for later use
                FILE* secret_key = fopen("secret.key","wb");
                export_tfheGateBootstrappingSecretKeySet_toFile(secret_key, key);
                fclose(secret_key);

                //export the cloud key to a file (for the cloud)
                FILE* cloud_key = fopen("cloud.key","wb");
                export_tfheGateBootstrappingCloudKeySet_toFile(cloud_key, &key->cloud);
                fclose(cloud_key);
            

                //**************//
                //clean up all pointers
                delete_gate_bootstrapping_secret_keyset(key);
                delete_gate_bootstrapping_parameters(params);

                Hasher hasher = Hasher(100, seed, "newProject");

                hasher.generateRSAKey();
    //hasher.exportKey();
    //hasher.exportCloudKey();
    //hasher.exportParams();
}

/***
 * Take the encrypted offer and key, decrypt the key and then return the TFHE cipher
 * @arg AESKeyName: name of the file with the encrypted AES keyname
 * @arg offerName: name of the file with the encrypted offer
 * 
 * ***/
LweSample *decryptOffer(string AESKeyName, string offerName)
{
    aes_iv_t iv{};
    CryptoPP::FileSource fs("newIV.data", true, new CryptoPP::ArraySink(iv.data(), iv.size()));

    std::string cloudPrefix = offerName;
    boost::erase_all(cloudPrefix, "offer");
    string cloudData = cloudPrefix+"cloud.data";

    uint32_t seed[] = {314, 1592, 657};
    Hasher hasher = Hasher(100, seed,"decryptOffer");
    Comparator cloud = Comparator(cloudData,"cloud.key", 1, hasher.cipherInt(0), hasher.cipherInt(10));

    cout << "Step0. decipher AES key" << endl;
    cloud.RSADecryption(AESKeyName, cloudPrefix);

    cout << "Step1. fetch deciphered AES key" << endl;
    boost::erase_all(cloudPrefix,"AES.data");
    cout << "[CLOUD preFIX]: " << cloudPrefix << endl;

    aes_key_t key2 = cloud.getAESKey(cloudPrefix+"AES2.key");

    cout << "Step2. Decipher offer with AES key" << endl;
    cloud.decrypt(key2, iv, offerName, cloudPrefix+"cloud.data");

    cout << "Step3. Get FHE-ciphered offer from file and put it in ciphertext1" << endl;
    cloud.getCipher(cloudPrefix+"cloud.data");

    cout << "Offer decryption done" << endl;
    return cloud.ciphertext1[0];
    // std::clock_t start;
    // start = std::clock();
    // //cloud.getMinimum();
    // std::cout << "Time: " << (std::clock() - start) / (double)(CLOCKS_PER_SEC / 1000) << " ms" << std::endl;
}

