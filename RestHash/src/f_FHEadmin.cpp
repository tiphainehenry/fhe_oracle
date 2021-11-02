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

#include "./utils/verif_FHE_comparison.cc"

using namespace CryptoPP;
using namespace std;

using aes_key_t = std::array<byte, CryptoPP::AES::DEFAULT_KEYLENGTH>;
using aes_iv_t = std::array<byte, CryptoPP::AES::BLOCKSIZE>;


string store_fhe_keys_to_ipfs(string path_to_tmp)
{
    //ROLES: FHE ADMIN AND ORACLE
    ipfs::Json tmp;
    ipfs::Client client("localhost", 5001);
    client.FilesAdd({{"secret.key", ipfs::http::FileUpload::Type::kFileName, path_to_tmp + "secret.key"},
                     {"cloud.key", ipfs::http::FileUpload::Type::kFileName, path_to_tmp + "cloud.key"},
                     {"params.metadata", ipfs::http::FileUpload::Type::kFileName, path_to_tmp + "params.metadata"}},
                    &tmp);

    string keyTypeShort[3] = {
        "(FHE private key to cipher clear offers)",
        "(FHE public key for oracle ciphered comparisons)",
        "(FHE params metadata used to process ciphers)"};

    string response;
    for (size_t i = 0; i < tmp.size(); i++)
    {
        cout << "==> " << tmp[i]["hash"] << keyTypeShort[i] << endl;
        response = response + tmp[i]["hash"].dump() + keyTypeShort[i] + "/n";
    }

    return response;
}

void generate_fhe_params_and_keyset()
{
    /// ROLE: FHE ADMIN 

    // FHE params
    const int minimum_lambda = 110;
    TFheGateBootstrappingParameterSet *params = new_default_gate_bootstrapping_parameters(minimum_lambda);

    FILE *params_file = fopen(".tmp/params.metadata", "wb"); // export the parameter to file for later use
    export_tfheGateBootstrappingParameterSet_toFile(params_file, params);
    fclose(params_file);

    //generate a random key
    uint32_t seed[] = {314, 1592, 657};
    tfhe_random_generator_setSeed(seed, 3);
    TFheGateBootstrappingSecretKeySet *key = new_random_gate_bootstrapping_secret_keyset(params);

    //export the secret key to file for later use
    FILE *secret_key = fopen(".tmp/secret.key", "wb");
    export_tfheGateBootstrappingSecretKeySet_toFile(secret_key, key);
    fclose(secret_key);

    //export the cloud key to a file (for the cloud)
    FILE *cloud_key = fopen(".tmp/cloud.key", "wb");
    export_tfheGateBootstrappingCloudKeySet_toFile(cloud_key, &key->cloud);
    fclose(cloud_key);

    // clean up pointers
    delete_gate_bootstrapping_parameters(params);
    delete_gate_bootstrapping_secret_keyset(key);
}

////***********************************////
////*********** ASK VERIF *************////





string utils_decipherArgmax(int offerNbr)
{
    //// ROLE:FHE ADMIN

    std::Verif verifz = std::Verif(offerNbr);
    
    return verifz.decrypt(".tmp/answer.data"); 
}
////***********************************////
////***********************************////
