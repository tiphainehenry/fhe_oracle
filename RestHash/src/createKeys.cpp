#include <ipfs/client.h>
#include <boost/algorithm/string.hpp>
#include <iostream>
#include <nlohmann/json.hpp>
#include <sstream>
#include <stdexcept>
#include "../include/handler.h"
#include "utils/utils.cpp"
#include "f_EndUser.cpp"
#include "f_FHEadmin.cpp"
#include "f_Oracle.cpp"



// #include "../ParserData.cc"

using Json = nlohmann::json;


int CreateKeys(){
    string path_to_tmp = get_path("fd_data");
    string path_to_ipfs_folder=get_path("fd_ipfs");
    string path_to_test = get_path("fd_testjson");
    print_info("Creating new tender (generation of FHE and RSA keys and storage to ipfs)");


    try{
        // key gen
        generate_fhe_params_and_keyset();
        utils_generateRSAKey();
        //print_info("RSA and FHE keys generated");

        // ipfs storage of the RSA key
        string response = store_rsa_keys_to_ipfs(path_to_tmp);

        print_info("OK - New set of keys generated");
    }
    catch (const std::exception &e){
        cout << "[ERROR] --> in new tender" << endl;
        std::cerr << e.what() << std::endl;
    }
    return 200;
}
