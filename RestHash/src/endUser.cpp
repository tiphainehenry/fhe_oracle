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
#include "../include/hascompare.h"
#include "../RSAToTFHE.cc"
#include "../Cloud.cc"

using namespace CryptoPP;
using namespace std;

using aes_key_t = std::array<byte, CryptoPP::AES::DEFAULT_KEYLENGTH>;
using aes_iv_t = std::array<byte, CryptoPP::AES::BLOCKSIZE>;

/***
 * Get a file from the IPFS server and save it locally
 * @return the name of the file saved
 * 
 * **/
string utils_ipfsToFile(string ipfsAddress, string offerName, ipfs::Client client, string fileType)
{
    try
    {
        //std::cout << "i am a test" << endl;
        ofstream file;
        std::stringstream contents;
        client.FilesGet(ipfsAddress, &contents);
        //std::cout << "me too" << endl;
        file.open(offerName + "." + fileType);
        //std::cout << "yo tambien" << endl;

        file << contents.str();
        file.close();
    }
    catch (const std::exception &e)
    {
        cout << "[ERROR] --> in ipfstofile" << endl;
        std::cerr << e.what() << std::endl;
    }
    return (offerName + "." + fileType);
}

string utils_computeNumberOfOffers(http_request message)
{
    std::string prefix = "";

    try
    {
        auto tmpbis = message.extract_json().get(); // reading test.json data stored as tmp
        int cnt = 0;
        for (auto it = tmpbis.as_object().cbegin(); it != tmpbis.as_object().cend(); ++it) // for each ciphered offer do:
        {
            cnt = cnt + 1;
        }
        std::string prefix = std::to_string(cnt + 1) + '.';
    }
    catch (const std::exception &e)
    {
        cout << "[ERROR] --> in computeNumberOfOffers" << endl;
        std::cerr << e.what() << std::endl;
    }
    return prefix;
}

CryptoPP::RSA::PublicKey utils_generateRSAKey()
{
    AutoSeededRandomPool rng;
    InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(rng, 1024);
    CryptoPP::RSA::PrivateKey privateKey(params);
    CryptoPP::RSA::PublicKey publicKey(params);

    publicKey.DEREncode(FileSink("publicKey.key", true).Ref());
    privateKey.DEREncode(FileSink("privateKey.key", true).Ref());
    return publicKey;
}

void utils_export2Data(std::vector<LweSample *> ciphertext, std::string filename, TFheGateBootstrappingParameterSet *params)
{
    FILE *cloud_data = fopen(filename.c_str(), "wb");
    for (size_t j = 0; j < ciphertext.size(); j++)
    {
        for (int i = 0; i < 16; i++)
            export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext[j][i], params);
    }
    fclose(cloud_data);
}

void utils_RSAEncryption(string filename, CryptoPP::RSA::PublicKey publicKey, AutoSeededRandomPool &rng)
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

aes_key_t utils_generate_cipher_AESKey(string AESfilename, string RSAfilename)
{
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
    LweSample *cipherText = new_gate_bootstrapping_ciphertext_array(16, params);
    for (size_t i = 0; i < 16; i++)
    {
        bootsSymEncrypt(&cipherText[i], (message >> i) & 1, key);
    }
    return (cipherText);
}

/***
 * Take the encrypted offer and key, decrypt the key and then return the TFHE cipher
 * @arg AESKeyName: name of the file with the encrypted AES keyname
 * @arg offerName: name of the file with the encrypted offer
 * 
 * ***/
LweSample *utils_decryptOffer(string prefix, string AESKeyName, string offerName)
{
    FILE *params_file = fopen("params.metadata", "rb");
    TFheGateBootstrappingParameterSet *params = new_tfheGateBootstrappingParameterSet_fromFile(params_file);
    fclose(params_file);

    FILE *secret_key = fopen("secret.key", "rb");
    TFheGateBootstrappingSecretKeySet *key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
    fclose(secret_key);

    /// decipher AES layer and store FHE offers

    /// decryptOffer
    aes_iv_t iv_decrypt{};
    string ivFileName = prefix + "newIV.data";
    CryptoPP::FileSource fs(ivFileName.c_str(), true, new CryptoPP::ArraySink(iv_decrypt.data(), iv_decrypt.size()));

    std::string cloudPrefix = offerName;
    boost::erase_all(cloudPrefix, "offer");
    string cloudData = cloudPrefix + "cloud.data";

    Comparator cloud = Comparator(cloudData, "cloud.key", 3, utils_cipherInt(0, params, key), utils_cipherInt(10, params, key));

    cout << "Step0. decipher AES key" << endl;
    cloud.RSADecryption(AESKeyName, cloudPrefix);

    cout << "Step1. fetch deciphered AES key" << endl;
    boost::erase_all(cloudPrefix, "AES.data");

    aes_key_t key2 = cloud.getAESKey(cloudPrefix + "AES2.key");

    cout << "Step2. Decipher offer with AES key" << endl;
    cloud.decrypt(key2, iv_decrypt, offerName, cloudPrefix + "cloud.data");

    cout << "Step3. Get FHE-ciphered offer from file and put it in ciphertext1" << endl;

    //reads the cloud key from file
    FILE *cloud_key = fopen("cloud.key", "rb");
    TFheGateBootstrappingCloudKeySet *bk = new_tfheGateBootstrappingCloudKeySet_fromFile(cloud_key);
    fclose(cloud_key);

    //if necessary, the params are inside the key
    const TFheGateBootstrappingParameterSet *cloud_params = bk->params;

    //LweSample* cipheredArgmaxVector = new_gate_bootstrapping_ciphertext_array(16, params);
    //reads the 2x16 ciphertexts from the cloud file
    cout << "start reading" << endl;

    //read the 2x16 ciphertexts
    LweSample *ciphertext1 = new_gate_bootstrapping_ciphertext_array(16, cloud_params);

    string cloudDataFileName = cloudPrefix + "cloud.data";
    FILE *cloud_data1 = fopen(cloudDataFileName.c_str(), "rb");
    for (int i = 0; i < 16; i++)
        import_gate_bootstrapping_ciphertext_fromFile(cloud_data1, &ciphertext1[i], params);
    fclose(cloud_data1);
    cout << "stop reading" << endl;

    //cloud.getCipher(cloudPrefix + "cloud.data");

    //decrypt and rebuild the 16-bit plaintext answer
    int16_t int_answer1 = 0;
    for (int i=0; i<16; i++) {
            int ai1 = bootsSymDecrypt(&ciphertext1[i], key);
            int_answer1 |= (ai1<<i);
    }

    cout << "Offer decryption done (initially " <<int_answer1<<")"<< endl;

    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);

    //delete_gate_bootstrapping_ciphertext_array(16, result);
    //delete_gate_bootstrapping_ciphertext_array(16, cipheredArgmaxVector);
    //delete_gate_bootstrapping_ciphertext_array(16, ciphertext1);
    delete_gate_bootstrapping_cloud_keyset(bk);

    return ciphertext1;
    // std::clock_t start;
    // start = std::clock();
    // //cloud.getMinimum();
    // std::cout << "Time: " << (std::clock() - start) / (double)(CLOCKS_PER_SEC / 1000) << " ms" << std::endl;
}

void addAESLayer(std::string prefix, std::string RSAfilename)
{

    // GENERATE AES KEY PEER AND CIPHER PRIVATE KEY WITH RSA
    aes_key_t AESkey = utils_generate_cipher_AESKey(prefix + "AES.key", RSAfilename);

    // GENERATE IV
    aes_iv_t iv{};
    CryptoPP::AutoSeededRandomPool AESrng{};
    AESrng.GenerateBlock(iv.data(), iv.size());
    string ivFileName = prefix + "newIV.data";
    CryptoPP::ArraySource as(iv.data(), iv.size(), true, new CryptoPP::FileSink(ivFileName.c_str()));

    // CIPHER FHE OFFER WITH AES PUBLIC KEY
    utils_encryptFHEOfferWithAES(AESkey, iv, prefix + "cloud.data", prefix + "AES.data");
}

void cipherOfferWithFHE(string prefix, int value)
{
    FILE *params_file = fopen("params.metadata", "rb");
    TFheGateBootstrappingParameterSet *params = new_tfheGateBootstrappingParameterSet_fromFile(params_file);
    fclose(params_file);

    FILE *secret_key = fopen("secret.key", "rb");
    TFheGateBootstrappingSecretKeySet *key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
    fclose(secret_key);

    LweSample *ciphertext1 = new_gate_bootstrapping_ciphertext_array(16, params);
    for (int i = 0; i < 16; i++)
    {
        bootsSymEncrypt(&ciphertext1[i], (value >> i) & 1, key);
    }

    //************************************************//
    //******************* debug 
    //************************************************//

    //decrypt and rebuild the 16-bit plaintext answer
    int16_t int_answer = 0;
    for (int i=0; i<16; i++) {
        int ai = bootsSymDecrypt(&ciphertext1[i], key);
        int_answer |= (ai<<i);
    }

    std::cout << "offer is worth: " << int_answer << std::endl;
    //************************************************//
    //************************************************//


    string filename = prefix + "cloud.data";
    FILE *cloud_data = fopen(filename.c_str(), "wb");
    for (int i = 0; i < 16; i++)
        export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext1[i], params);
    fclose(cloud_data);

    //clean up all pointers
    delete_gate_bootstrapping_ciphertext_array(16, ciphertext1); //...
    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);
}

void utils_compare_bit(LweSample *result, const LweSample *a, const LweSample *b, const LweSample *lsb_carry, LweSample *tmp, const TFheGateBootstrappingCloudKeySet *bk)
{
    bootsXNOR(tmp, a, b, bk);
    bootsMUX(result, tmp, lsb_carry, a, bk);
}

LweSample *addition(const LweSample *a, const LweSample *b, const TFheGateBootstrappingCloudKeySet *bk)
{
    LweSample *res = new_gate_bootstrapping_ciphertext_array(16, bk->params);
    LweSample *tt = new_gate_bootstrapping_ciphertext_array(16, bk->params);
    full_adder(res, a, b, 16, bk);

    FILE *answer_data = fopen("answer.data", "wb");
    for (int i = 0; i < 16; i++)
    {
        export_gate_bootstrapping_ciphertext_toFile(answer_data, &res[i], bk->params);
    }
    fclose(answer_data);
    return (res);
}

LweSample *minimum(
    vector<LweSample *> a, 
    const int nb_bits, 
    const TFheGateBootstrappingCloudKeySet *bk, 
    int x, 
    int y, 
    LweSample * c_zero, 
    LweSample * c_ten)
{
    LweSample *tmps = new_gate_bootstrapping_ciphertext_array(2, bk->params);
    LweSample *res = new_gate_bootstrapping_ciphertext_array(16, bk->params);

    bootsCONSTANT(&tmps[0], 0, bk);

    for (int i = 0; i < nb_bits; i++)
        utils_compare_bit(&tmps[0], &a[x][i], &a[y][i], &tmps[0], &tmps[1], bk);
    for (int i = 0; i < nb_bits; i++)
        bootsMUX(&res[i], &tmps[0], &c_ten[i], &c_zero[i], bk);
    delete_gate_bootstrapping_ciphertext_array(2, tmps);
    return (res);
}

/***
         *  Function taking FHE offers as input and comparing the value to obtain the ordered vector 
         **/
void utils_getMinimum(LweSample * c_zero, LweSample * c_ten,
                vector<LweSample *> offers)
{

    FILE *cloud_key = fopen("cloud.key", "rb");
    TFheGateBootstrappingCloudKeySet *bk = new_tfheGateBootstrappingCloudKeySet_fromFile(cloud_key);
    fclose(cloud_key);

    //************************************************//
    //******************* debug 
    //************************************************//

    //reads the cloud key from file
    FILE* secret_key = fopen("secret.key","rb");
    TFheGateBootstrappingSecretKeySet* key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
    fclose(secret_key);

    for (size_t j = 0; j < offers.size(); j++)
            {


            //decrypt and rebuild the 16-bit plaintext answer
            int16_t int_answer = 0;
            for (int i=0; i<16; i++) {
                int ai = bootsSymDecrypt(&offers[j][i], key);
                int_answer |= (ai<<i);
            }

            std::cout << "offer " << j << "was worth: " << int_answer << std::endl;

        }
    delete_gate_bootstrapping_secret_keyset(key);

    //************************************************//
    //************************************************//

    //
    vector<LweSample *> cipheredArgmaxVector;
    for (size_t i = 0; i < offers.size(); i++)
            {
                cipheredArgmaxVector.push_back(new_gate_bootstrapping_ciphertext_array(16, bk->params));
            }



    // LAUCH COMPARISON
    for (size_t i = 0; i < offers.size(); i++)
    {
        LweSample *tmp = c_zero;
        for (size_t j = 0; j < offers.size(); j++)
        {
            cout << i << " / " << j << endl;
            if (j != i)
                tmp = addition(tmp, minimum(offers, 16, bk, i, j, c_zero, c_ten), bk);
            else
                tmp = addition(tmp, c_ten, bk);
        }
        cipheredArgmaxVector[i] = tmp;
    }

    // EXPORT ARGMAX (COMPARISON OUTPUTS) 
    FILE *cloud_data = fopen("answer.data", "wb");
    for (size_t j = 0; j < cipheredArgmaxVector.size(); j++)
    {
        for (int i = 0; i < 16; i++)
            export_gate_bootstrapping_ciphertext_toFile(cloud_data, &cipheredArgmaxVector[j][i], bk->params);
    }
    fclose(cloud_data);

    delete_gate_bootstrapping_cloud_keyset(bk);

}


/***
 * 
 * Take a vector of cipher and use cloud.getMinimum() to compare them
 * @arg offerNbr: number of offers to compare
 * @arg cipherVector: Vector of all the cipher to compare
 * @warning NOT WORKING 
 * @todo WORK IN PROGRESS
 * 
 * ***/
void utils_compare(vector<LweSample *> offers, int offerNbr)
{
    FILE *params_file = fopen("params.metadata", "rb");
    TFheGateBootstrappingParameterSet *params = new_tfheGateBootstrappingParameterSet_fromFile(params_file);
    fclose(params_file);

    FILE *secret_key = fopen("secret.key", "rb");
    TFheGateBootstrappingSecretKeySet *key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
    fclose(secret_key);

    LweSample * c_zero = utils_cipherInt(0, params, key);
    LweSample * c_ten = utils_cipherInt(10, params, key);

    std::clock_t start;
    start = std::clock();
    utils_getMinimum(c_zero, c_ten, offers);

    std::cout << "Time: " << (std::clock() - start) / (double)(CLOCKS_PER_SEC / 1000) << " ms" << std::endl;

    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);
}

void utils_decipherArgmax(int offerNbr)
{
    std::Verif verifz = std::Verif(offerNbr);
    verifz.decrypt("answer.data");
}
