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
#include <string>

#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>

#include <time.h>

#include "../include/handler.h"

// #include "utils/utils.cpp"

using namespace CryptoPP;
using namespace std;

using aes_key_t = std::array<CryptoPP::byte, CryptoPP::AES::DEFAULT_KEYLENGTH>;
using aes_iv_t = std::array<CryptoPP::byte, CryptoPP::AES::BLOCKSIZE>;

string store_rsa_keys_to_ipfs(string path_to_tmp)
{
    // ROLES: FHE ADMIN AND ORACLE
    ipfs::Json tmp;
    // Configure IPFS
    std::string ipfsConfig = get_ipfs_config();
    ipfs::Client client("ipfs.infura.io", 5001, "", "https://");
    if (ipfsConfig == "local")
    {
        ipfs::Client client("localhost", 5001);
    }
    // problem here
    print_debug("path = " + path_to_tmp);
    client.FilesAdd({{"publicKey.key", ipfs::http::FileUpload::Type::kFileName, path_to_tmp + "publicKey.key"}},
                    &tmp);

    string keyTypeShort[1] = {
        "(RSA public key to cipher AES keys)"};
    string response;
    for (size_t i = 0; i < tmp.size(); i++)
    {
        cout << "==> " << tmp[i]["hash"] << keyTypeShort[i] << endl;
        response = response + tmp[i]["hash"].dump() + keyTypeShort[i] + "/n";
    }

    return response;
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

/***
 *  Decrypt the AES key with the "./publicKey.key"
 * */
void RSADecryption(std::string filename, std::string prefix)
{

    // cout <<"entering rsa decryption"<< endl;
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSAES_OAEP_SHA_Decryptor dec;
    dec.AccessKey().BERDecode(CryptoPP::FileSource(get_filename("RSA_sk").c_str(), true).Ref());

    // compute prefix and generate AES2.key filename
    std::string AES2Prefix = filename;
    boost::erase_all(AES2Prefix, "AES.key");
    std::string clearedAESFN = AES2Prefix.append("AES2.key");

    char *char_arr;
    string str_obj(clearedAESFN);
    char_arr = &str_obj[0];
    // std::ifstream in{"AES.key", std::ios::binary};
    CryptoPP::FileSource ss2(filename.c_str(), true,
                             new CryptoPP::PK_DecryptorFilter(rng, dec,
                                                              new CryptoPP::FileSink(char_arr)) // PK_DecryptorFilter
    );

    // return 'ok';                                                                             // StringSource
}
/***
 * Get AES key from file
 * */
aes_key_t getAESKey(string filename)
{
    aes_key_t key;
    CryptoPP::FileSource fs(filename.c_str(), true, new CryptoPP::ArraySink(key.data(), key.size()));
    return key;
}

CryptoPP::RSA::PublicKey utils_generateRSAKey()
{
    /// ROLE: ORACLE
    AutoSeededRandomPool rng;
    InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(rng, 1024);
    CryptoPP::RSA::PrivateKey privateKey(params);
    CryptoPP::RSA::PublicKey publicKey(params);

    string RSA_pk = get_filename("RSA_pk");
    publicKey.DEREncode(FileSink(RSA_pk.c_str(), true).Ref());

    string RSA_sk = get_filename("RSA_sk");
    privateKey.DEREncode(FileSink(RSA_sk.c_str(), true).Ref());
    return publicKey;
}

/***
 * Decrypts the offer encrypted with AES+FHE and the AES key encrypted in RSA.
 * @arg prefix: offer prefix (following the order of the vector of offers to compare)
 * @arg AESKeyName: name of the file with the encrypted AES keyname
 * @arg offerName: name of the file with the encrypted offer
 * @arg numOffers: number of total offers (to instantiate cloud)
 *
 * @return FHE offer
 * ***/
vector<LweSample *> utils_decryptOffer(string prefix, int numOffers, vector<LweSample *> clearedOffers)
{
    /// ROLE: ORACLE

    string fd_data = GetCurrentWorkingDir() + "/" + get_path("fd_data");

    string AESKeyName = fd_data + prefix + "AES.key";
    string offerName = fd_data + prefix + "AES.data";

    // load params and keys
    string FHE_metadata = get_filename("FHE_metadata");
    FILE *params_file = fopen(FHE_metadata.c_str(), "rb");
    TFheGateBootstrappingParameterSet *params = new_tfheGateBootstrappingParameterSet_fromFile(params_file);
    fclose(params_file);

    string FHE_pk = get_filename("FHE_pk");
    FILE *cloud_key = fopen(FHE_pk.c_str(), "rb"); // reads the cloud key from file
    TFheGateBootstrappingCloudKeySet *bk = new_tfheGateBootstrappingCloudKeySet_fromFile(cloud_key);
    fclose(cloud_key);
    const TFheGateBootstrappingParameterSet *cloud_params = bk->params; // the params are inside the key

    /// decipher AES layer and store FHE offers
    aes_iv_t iv_decrypt{};
    string ivFileName = fd_data + prefix + "newIV.data";
    CryptoPP::FileSource fs(ivFileName.c_str(), true, new CryptoPP::ArraySink(iv_decrypt.data(), iv_decrypt.size()));

    std::string cloudPrefix = offerName;
    boost::erase_all(cloudPrefix, "offer");
    string cloudData = fd_data + cloudPrefix + "cloud.data";

    // Comparator cloud = Comparator(cloudData, "tmp/cloud.key", numOffers, utils_cipherInt(0, params, key), utils_cipherInt(10, params, key));

    // decipher and fetch AES key
    RSADecryption(AESKeyName, cloudPrefix);
    boost::erase_all(cloudPrefix, "AES.data"); // compute file prefix
    aes_key_t key2 = getAESKey(cloudPrefix + "AES2.key");

    // remove AES layer of the offer and save to "prefix.cloud.data"
    decrypt(key2, iv_decrypt, offerName, cloudPrefix + "cloud.data");

    // retrieve FHE-ciphered offer from file
    LweSample *ciphertext = new_gate_bootstrapping_ciphertext_array(16, cloud_params); // read the 2x16 ciphertexts
    string cloudDataFileName = cloudPrefix + "cloud.data";
    FILE *cloud_data1 = fopen(cloudDataFileName.c_str(), "rb");
    for (int i = 0; i < 16; i++)
        import_gate_bootstrapping_ciphertext_fromFile(cloud_data1, &ciphertext[i], params);
    fclose(cloud_data1);

    // clean environment
    delete_gate_bootstrapping_parameters(params);
    delete_gate_bootstrapping_cloud_keyset(bk);

    clearedOffers.push_back(ciphertext);
    return clearedOffers;
}

/***
 * Decrypts the offer encrypted with AES+FHE and the AES key encrypted in RSA.
 * @arg prefix: offer prefix (following the order of the vector of offers to compare)
 * @arg AESKeyName: name of the file with the encrypted AES keyname
 * @arg offerName: name of the file with the encrypted offer
 * @arg numOffers: number of total offers (to instantiate cloud)
 *
 * @return FHE offer
 * ***/
vector<LweSample *> utils_decryptOffer_withIPFS(string prefix, int numOffers, vector<LweSample *> clearedOffers)
{
    //// ROLE:ORACLE

    string AESKeyName = GetCurrentWorkingDir() + "/" + get_path("fd_ipfs") + prefix + "AES.key";
    string offerName = GetCurrentWorkingDir() + "/" + get_path("fd_ipfs") + prefix + "AES.data";

    // load params and keys
    string FHE_metadata = get_filename("FHE_metadata");
    FILE *params_file = fopen(FHE_metadata.c_str(), "rb");
    TFheGateBootstrappingParameterSet *params = new_tfheGateBootstrappingParameterSet_fromFile(params_file);
    fclose(params_file);

    string FHE_pk = get_filename("FHE_pk");
    FILE *cloud_key = fopen(FHE_pk.c_str(), "rb"); // reads the cloud key from file
    TFheGateBootstrappingCloudKeySet *bk = new_tfheGateBootstrappingCloudKeySet_fromFile(cloud_key);
    fclose(cloud_key);
    const TFheGateBootstrappingParameterSet *cloud_params = bk->params; // the params are inside the key

    /// decipher AES layer and store FHE offers
    string fd_data = GetCurrentWorkingDir() + "/" + get_path("fd_data");

    aes_iv_t iv_decrypt{};
    string ivFileName = fd_data + prefix + "newIV.data";
    CryptoPP::FileSource fs(ivFileName.c_str(), true, new CryptoPP::ArraySink(iv_decrypt.data(), iv_decrypt.size()));

    std::string cloudPrefix = offerName;
    boost::erase_all(cloudPrefix, "offer");
    string cloudData = fd_data + cloudPrefix + "cloud.data";

    // Comparator cloud = Comparator(cloudData, "tmp/cloud.key", numOffers, utils_cipherInt(0, params, key), utils_cipherInt(10, params, key));

    // decipher and fetch AES key
    RSADecryption(AESKeyName, cloudPrefix);
    boost::erase_all(cloudPrefix, "AES.data"); // compute file prefix
    aes_key_t key2 = getAESKey(cloudPrefix + "AES2.key");

    // remove AES layer of the offer and save to "prefix.cloud.data"
    decrypt(key2, iv_decrypt, offerName, cloudPrefix + "cloud.data");

    // retrieve FHE-ciphered offer from file
    LweSample *ciphertext = new_gate_bootstrapping_ciphertext_array(16, cloud_params); // read the 2x16 ciphertexts
    string cloudDataFileName = cloudPrefix + "cloud.data";
    FILE *cloud_data1 = fopen(cloudDataFileName.c_str(), "rb");
    for (int i = 0; i < 16; i++)
        import_gate_bootstrapping_ciphertext_fromFile(cloud_data1, &ciphertext[i], params);
    fclose(cloud_data1);

    // clean environment
    delete_gate_bootstrapping_parameters(params);
    delete_gate_bootstrapping_cloud_keyset(bk);

    clearedOffers.push_back(ciphertext);
    return clearedOffers;
}

////*********************************////
////*********** COMPARE *************////

void utils_compare_bit(LweSample *result, const LweSample *a, const LweSample *b, const LweSample *lsb_carry, LweSample *tmp, const TFheGateBootstrappingCloudKeySet *bk)
{
    //// ROLE:ORACLE

    bootsXNOR(tmp, a, b, bk);
    bootsMUX(result, tmp, lsb_carry, a, bk);
}

LweSample *addition(const LweSample *a, const LweSample *b, const TFheGateBootstrappingCloudKeySet *bk)
{
    //// ROLE:ORACLE

    LweSample *res = new_gate_bootstrapping_ciphertext_array(16, bk->params);
    LweSample *tt = new_gate_bootstrapping_ciphertext_array(16, bk->params);
    full_adder(res, a, b, 16, bk);

    string cleared_data = get_filename("cleared_data");
    FILE *answer_data = fopen(cleared_data.c_str(), "wb");
    for (int i = 0; i < 16; i++)
    {
        export_gate_bootstrapping_ciphertext_toFile(answer_data, &res[i], bk->params);
    }
    fclose(answer_data);
    return (res);
}

/***
 * Adds 2 or more ciphered offers
 * @arg offers: vector of FHE offers
 * @arg offerNbr: the number of offers
 *
 * @return encrypted result
 * ***/
LweSample *addition_multiple(vector<LweSample *> offers, int offerNbr)
{

    const int nb_bits = 16;

    string FHE_pk = get_filename("FHE_pk");
    FILE *cloud_key = fopen(FHE_pk.c_str(), "rb"); // reads the bootstrapping key from file
    TFheGateBootstrappingCloudKeySet *bk = new_tfheGateBootstrappingCloudKeySet_fromFile(cloud_key);
    fclose(cloud_key);

    LweSample *tmp = new_gate_bootstrapping_ciphertext_array(16, bk->params);
    LweSample *result = new_gate_bootstrapping_ciphertext_array(16, bk->params);

    full_adder(tmp, offers[0], offers[1], 16, bk);
    for (int index = 2; index < offerNbr; index++)
    {
        for (int j = 0; j < nb_bits; j++)
        {
            bootsCOPY(&result[j], &tmp[j], bk);
        }
        full_adder(tmp, result, offers[index], 16, bk);
    }
    for (int i = 0; i < nb_bits; i++)
    {
        bootsCOPY(&result[i], &tmp[i], bk);
    }

    string cleared_data = get_filename("cleared_data");
    FILE *cloud_data = fopen(cleared_data.c_str(), "wb");
    for (int j = 0; j < nb_bits; j++)
    {
        export_gate_bootstrapping_ciphertext_toFile(cloud_data, &result[j], bk->params);
    }
    fclose(cloud_data);
    return (result);
}

/***
 * Substracts 2 or more ciphered offers
 * see [1] in function for further details
 * @arg offers: vector of FHE offers
 * @arg offerNbr: the number of offers
 *
 *
 * @return encrypted result
 * ***/
LweSample *substraction_multiple(vector<LweSample *> offers, int offerNbr)
{

    const int nb_bits = 16;

    string FHE_pk = get_filename("FHE_pk");
    FILE *cloud_key = fopen(FHE_pk.c_str(), "rb"); // reads the cloud key from file
    TFheGateBootstrappingCloudKeySet *bk = new_tfheGateBootstrappingCloudKeySet_fromFile(cloud_key);
    fclose(cloud_key);

    LweSample *tmp = new_gate_bootstrapping_ciphertext_array(16, bk->params);
    LweSample *result = new_gate_bootstrapping_ciphertext_array(16, bk->params);

    full_subtract(tmp, offers[0], offers[1], keyset);
    for (int index = 2; index < offerNbr; index++)
    {
        for (int j = 0; j < nb_bits; j++)
        {
            bootsCOPY(&result[j], &tmp[j], keyset);
        }
        full_subtract(tmp, result, offers[index], keyset);
    }

    for (int j = 0; j < nb_bits; j++)
    {
        bootsCOPY(&result[j], &tmp[j], keyset);
    }

    string cleared_data = get_filename("cleared_data");
    FILE *cloud_data = fopen(cleared_data.c_str(), "wb");
    for (int j = 0; j < nb_bits; j++)
    {

        export_gate_bootstrapping_ciphertext_toFile(cloud_data, &result[j], bk->params);
    }
    fclose(cloud_data);
    return (result);
}

LweSample *minimum(
    vector<LweSample *> a,
    const int nb_bits,
    const TFheGateBootstrappingCloudKeySet *bk,
    int x,
    int y,
    LweSample *c_zero,
    LweSample *c_ten)
{
    //// ROLE:ORACLE

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
void utils_getMinimum(LweSample *c_zero, LweSample *c_ten,
                      vector<LweSample *> offers)
{
    //// ROLE:ORACLE

    string FHE_pk = get_filename("FHE_pk");
    FILE *cloud_key = fopen(FHE_pk.c_str(), "rb");
    TFheGateBootstrappingCloudKeySet *bk = new_tfheGateBootstrappingCloudKeySet_fromFile(cloud_key);
    fclose(cloud_key);

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

    // EXPORT ARGMAX (COMPARISON OUTPUTS) inside cleared_data file which refers to answer.data
    string cleared_data = get_filename("cleared_data");
    FILE *cloud_data = fopen(cleared_data.c_str(), "wb");
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

    //// ROLE:ORACLE

    string FHE_metadata = get_filename("FHE_metadata");
    FILE *params_file = fopen(FHE_metadata.c_str(), "rb");
    TFheGateBootstrappingParameterSet *params = new_tfheGateBootstrappingParameterSet_fromFile(params_file);
    fclose(params_file);

    string FHE_sk = get_filename("FHE_sk");
    FILE *secret_key = fopen(FHE_sk.c_str(), "rb");
    TFheGateBootstrappingSecretKeySet *key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
    fclose(secret_key);

    LweSample *c_zero = utils_cipherInt(0, params, key);
    LweSample *c_ten = utils_cipherInt(10, params, key);

    std::clock_t start;
    start = std::clock();
    utils_getMinimum(c_zero, c_ten, offers);

    std::cout << "Time: " << (std::clock() - start) / (double)(CLOCKS_PER_SEC / 1000) << " ms" << std::endl;

    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);
}
