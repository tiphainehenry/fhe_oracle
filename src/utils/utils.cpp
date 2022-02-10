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

#include <stdio.h>
#include <iostream>
#include <iomanip>
#include <cstdlib>
#include <cmath>
#include <sys/time.h>
#include <tfhe/tfhe.h>

#include "./include/handler.h"

#include "./include/polynomials.h"
#include "./include/lwesamples.h"
#include "./include/lwekey.h"
#include "./include/lweparams.h"
#include "./include/tlwe.h"
#include "./include/tgsw.h"
#include <nlohmann/json.hpp>

using Json = nlohmann::json;


using namespace std;
using namespace CryptoPP;
using namespace std;

using aes_key_t = std::array<byte, CryptoPP::AES::DEFAULT_KEYLENGTH>;
using aes_iv_t = std::array<byte, CryptoPP::AES::BLOCKSIZE>;


#include <stdio.h>  /* defines FILENAME_MAX */
// #define WINDOWS  /* uncomment this line to use it for windows.*/ 
#ifdef WINDOWS
#include <direct.h>
#define GetCurrentDir _getcwd
#else
#include <unistd.h>
#define GetCurrentDir getcwd
#endif
#include<iostream>

std::string GetCurrentWorkingDir( void ) {
  char buff[FILENAME_MAX];
  GetCurrentDir( buff, FILENAME_MAX );
  std::string current_working_dir(buff);
  return current_working_dir;
}


string myCompURLs=GetCurrentWorkingDir()+"/src/utils/url_filenames.json";

void print_info(string msg)
{
    cout << "[INFO] " << msg << endl;
}

void print_error(string msg)
{
    cout << "[ERROR] " << msg << endl;
}

void print_debug(string msg)
{
    cout << "[DEBUG] " << msg << endl;
}


string get_path(string query){
    std::ifstream ifs(myCompURLs);
    Json jf = Json::parse(ifs);
    string path= jf[query];
    return path;
}


string get_filename(string query){
    std::ifstream ifs(myCompURLs);
    Json jf = Json::parse(ifs);
    std::string tmpPath= jf["fd_data"];
    std::string myQuery = jf[query];
    std::string concat = tmpPath+myQuery; 
    return concat;
}

string get_ipfs_config(){
    std::ifstream ifs(myCompURLs);
    Json jf = Json::parse(ifs);
    std::string ipfsConfig= jf["ipfs_config"];
    return ipfsConfig;
}

/***
 * Get a file from the IPFS server and save it locally
 * @return the name of the file saved
 * 
 * **/
string utils_ipfsToFile(string ipfsAddress, string offerName, ipfs::Client client, string fileType)
{

    try
    {
        ofstream file;
        std::stringstream contents;
        client.FilesGet(ipfsAddress, &contents);
        file.open(offerName + "." + fileType);

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
        prefix = to_string(cnt + 1) + '.';
    }
    catch (const std::exception &e)
    {
        cout << "[ERROR] --> in computeNumberOfOffers" << endl;
        std::cerr << e.what() << std::endl;
    }
    return prefix;
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


void full_adder(LweSample *sum, const LweSample *x, const LweSample *y, const int32_t nb_bits,
                const TFheGateBootstrappingCloudKeySet *keyset) {
    const LweParams *in_out_params = keyset->params->in_out_params;
    // carries
    LweSample *carry = new_LweSample_array(2, in_out_params);
    // bootsSymEncrypt(carry, 0, keyset); // first carry initialized to 0
    bootsCONSTANT(carry, 0, keyset);
    LweSample *temp = new_LweSample_array(3, in_out_params);

    for (int32_t i = 0; i < nb_bits; ++i) {
        //sumi = xi XOR yi XOR carry(i-1) 
        bootsXOR(temp, x + i, y + i, keyset); // temp = xi XOR yi
        bootsXOR(sum + i, temp, carry, keyset);

        // carry = (xi AND yi) XOR (carry(i-1) AND (xi XOR yi))
        bootsAND(temp + 1, x + i, y + i, keyset); // temp1 = xi AND yi
        bootsAND(temp + 2, carry, temp, keyset); // temp2 = carry AND temp
        bootsXOR(carry + 1, temp + 1, temp + 2, keyset);
        bootsCOPY(carry, carry + 1, keyset);
    }
    bootsCOPY(sum, carry, keyset);

    delete_LweSample_array(3, temp);
    delete_LweSample_array(2, carry);
}


void comparison_MUX(LweSample *comp, const LweSample *x, const LweSample *y, const int32_t nb_bits,
                    const TFheGateBootstrappingSecretKeySet *keyset) {
    const LweParams *in_out_params = keyset->params->in_out_params;
    // carries
    LweSample *carry = new_LweSample_array(2, in_out_params);
    bootsSymEncrypt(carry, 1, keyset); // first carry initialized to 1
    // temps
    LweSample *temp = new_LweSample(in_out_params);

    for (int32_t i = 0; i < nb_bits; ++i) {
        bootsXOR(temp, x + i, y + i, &keyset->cloud); // temp = xi XOR yi
        bootsMUX(carry + 1, temp, y + i, carry, &keyset->cloud);
        bootsCOPY(carry, carry + 1, &keyset->cloud);
    }
    bootsCOPY(comp, carry, &keyset->cloud);

    delete_LweSample(temp);
    delete_LweSample_array(2, carry);
}
