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

handler::handler()
{
    //ctor
}
handler::handler(utility::string_t url) : m_listener(url)
{
    // m_listener.support(methods::GET, std::bind(&handler::handle_get, this, std::placeholders::_1));
    //m_listener.support(methods::PUT, std::bind(&handler::handle_put, this, std::placeholders::_1));
    m_listener.support(methods::POST, std::bind(&handler::handle_post, this, std::placeholders::_1));
    // m_listener.support(methods::DEL, std::bind(&handler::handle_delete, this, std::placeholders::_1));
}
handler::~handler()
{
    //dtor
}

void handler::handle_error(pplx::task<void> &t)
{
    try
    {
        t.get();
    }
    catch (...)
    {
        // Ignore the error, Log it if a logger is available
    }
}

//
// Get Request
//
void handler::handle_get(http_request message)
{
    //ucout << message.to_string() << endl;

    auto paths = http::uri::split_path(http::uri::decode(message.relative_uri().path()));

    message.relative_uri().path();
    message.relative_uri().query();
    //ucout << message.relative_uri().path() << endl;
    //ucout << message.relative_uri().query() << endl;

    message.reply(status_codes::OK, U("reading handler"))
        .then([](pplx::task<void> t)
              {
                  try
                  {
                      t.get();
                  }
                  catch (const std::exception &e)
                  {
                      cout << "[ERROR] --> in handle_get" << endl;
                      std::cerr << e.what() << std::endl;
                  }
              });

    return;
};

//
// A POST request
//
void handler::handle_post(http_request message)
{
    std::cout << "[INFO] Handling post request  (Path:" << message.relative_uri().path() << "|Query:" << message.relative_uri().query() << ")" << endl;
    auto queries = uri::split_query(message.relative_uri().query());

    string path_to_tmp = GetCurrentWorkingDir()+"/"+get_path("fd_data");
    string path_to_ipfs_folder=GetCurrentWorkingDir()+"/"+get_path("fd_ipfs");
    string path_to_test = GetCurrentWorkingDir()+"/";

    if (message.relative_uri().path() == "/newTender")
    {
        print_info("Creating new tender (generation of FHE and RSA keys and storage to ipfs)");

        if (queries.find("Hash") == queries.end())
        {
            message.reply(status_codes::InternalError, "No Hash provided");
        }
        else
        {
            try
            {
                // key gen
                generate_fhe_params_and_keyset();
                utils_generateRSAKey();

                print_info("RSA and FHE keys generated");

                // ipfs storage of the RSA key
                //string response = store_fhe_keys_to_ipfs(path_to_tmp);
                string response = store_rsa_keys_to_ipfs(path_to_tmp);

                message.reply(status_codes::OK, "New set of keys generated");
            }
            catch (const std::exception &e)
            {
                cout << "[ERROR] --> in new tender" << endl;
                std::cerr << e.what() << std::endl;
            }
        }
    }
    else if (message.relative_uri().path() == "/findBestOffer")
    {
        try
        {
            print_info("Find best offer");

            // Configure IPFS
            std::string ipfsConfig = get_ipfs_config();

            ipfs::Client client("ipfs.infura.io", 5001, "20s", "https://");
            if (ipfsConfig == "local") {        
                ipfs::Client client("localhost", 5001);
            } 

            vector<string> offerNames;
            vector<LweSample *> clearedOffers;
            auto tmp = message.extract_json().get();                                     // reading test.json data stored as tmp

            int numOffers =0;
            for (auto it = tmp.as_object().cbegin(); it != tmp.as_object().cend(); ++it) // for each ciphered offer do:
            {
                numOffers = numOffers+1;
            }

            int i =0;
            for (auto it = tmp.as_object().cbegin(); it != tmp.as_object().cend(); ++it) // for each ciphered offer do:
            {
                std::cout << "_______________________________________________________"
                          << "\n";

                offerNames.push_back(it->first);                      // store elem in vector offerNames
                string key = it->second.at(U("key")).as_string();     // fetch key ipfs hash
                string offer = it->second.at(U("offer")).as_string(); // fetch offer ipfs hash
                boost::erase_all(key, "\"");                          // clean variables
                boost::erase_all(offer, "\"");

                std::cout << "Deciphering Offer n°" << it->first << "\n";
                std::cout << "> KEY HASH : " << key << endl;
                std::cout << "> OFFER: " << offer << endl;

                // Retrieve key and offer IPFS data and save it locally
                
                std::string keyFileName = utils_ipfsToFile(key, path_to_ipfs_folder+it->first, client, "AES.key");
                std::string offerFileName = utils_ipfsToFile(offer, path_to_ipfs_folder+it->first, client, "AES.data");

                print_info("Offer IPFS data succesfully retrieved (AES key+ AES/FHE ciphered offer)");

                /// decipher AES layer and store FHE offers
                clearedOffers = utils_decryptOffer_withIPFS(std::to_string(i + 1) + ".", numOffers, clearedOffers);
                i=i+1;
            }

            print_info("Decipher of FHE offers ok (#=" + std::to_string(clearedOffers.size()) + ")");

            //  launch comparison on "clearedOffers" that contains the cipher of all offers,
            print_info("Launching comparison");
            utils_compare(clearedOffers, numOffers);

            //  decipher argmax for verification
            string winnerArgmax = utils_decipherArgmax(clearedOffers.size());
            message.reply(status_codes::OK, "Argmax id of best offer is "+winnerArgmax);
        }

        catch (const std::exception &e)
        {
            cout << "[ERROR] --> in find best offer" << endl;
            std::cerr << e.what() << std::endl;
        }
    }
    else if (message.relative_uri().path() == "/offer")             /// computation of the new offer (ciphered data and aes key)
    {
        try
        {
            ipfs::Json tmp;
            // Configure IPFS
            std::string ipfsConfig_ = get_ipfs_config();
            ipfs::Client client("ipfs.infura.io", 5001, "20s", "https://");

    
            if (ipfsConfig_ == "local") {        
                ipfs::Client client("localhost", 5001);
                std::cout<< "IPFS config = local"<<std::endl;
            } else if (ipfsConfig_ == "infura"){
                std::cout<< "IPFS config = infura"<<std::endl;
            }else{
                std::cout<< "IPFS config not recognized"<<std::endl;
            }

            string offer = queries["offer"];

            string prefix = "";
            Json tmp_json;

            // extract stored offers

            auto tmpbis = message.extract_json().get(); // reading test.json data stored as tmp

            cout<<tmpbis;

            int cnt = 0;
            for (auto it = tmpbis.as_object().cbegin(); it != tmpbis.as_object().cend(); ++it) // for each ciphered offer do:
            {
                cnt = cnt + 1;
                string key = it->second.at(U("key")).as_string();     // fetch key ipfs hash
                string offer = it->second.at(U("offer")).as_string(); // fetch offer ipfs hash
                boost::erase_all(key, "\"");                          // clean variables
                boost::erase_all(offer, "\"");
                tmp_json[to_string(cnt)]["key"] = key;
                tmp_json[to_string(cnt)]["offer"] = offer;
            }

            prefix = to_string(cnt + 1) + '.';
            registerMyOffer(offer, prefix);

            /// storage of new offer into ipfs
            client.FilesAdd(
                {{prefix + "AES.key", ipfs::http::FileUpload::Type::kFileName, path_to_tmp + prefix + "AES.key"},
                 {prefix + "AES.data", ipfs::http::FileUpload::Type::kFileName, path_to_tmp + prefix + "AES.data"}},
                &tmp);

            // append new offer hashes to test.json
            string new_key = tmp[1]["hash"].dump();
            string new_offer = tmp[0]["hash"].dump();
            boost::erase_all(new_key, "\""); // clean variables
            boost::erase_all(new_offer, "\"");

            tmp_json[to_string(cnt + 1)]["key"] = new_key;
            tmp_json[to_string(cnt + 1)]["offer"] = new_offer;

            std::ofstream o(path_to_test + "test.json");
            o << std::setw(4) << tmp_json << std::endl;

            // ipfs output display
            string keyTypeShort[4] = {
                " is RSA+AES key hash",
                " is AES+FHE data hash"};
            string reply = "OK- Offer created (RSA+AESkeyHash=" + tmp[0]["hash"].dump() + "|AES+FHEdataHash=" + tmp[1]["hash"].dump() + ")";

            print_info("Add offer ok");

            message.reply(status_codes::OK, reply.c_str());
        }
        catch (const std::exception &e)
        {
            cout << "[ERROR] --> in new offer" << endl;
            std::cerr << e.what() << std::endl;
        }
    }

    else if (message.relative_uri().path().find("/debug") != string::npos) {
        try
        {
            string num = message.relative_uri().path();
            num.erase(num.begin() + 0, num.begin() + 9);
            cout << "After erase(idx) : ";
            cout << num;

            print_debug("Launching test with " +num+ " offers");
            int numOffers = stoi(num);            
            string offers[numOffers];
            
            // fill in array randomly
            for(int i = 0; i < numOffers; i++){
                string randNum = to_string(rand() % 10); 
                offers[i] = randNum;              //= {"1000", "62", "340"};
                cout<<"offer:"<<i <<"="<<randNum<<endl;
            }

            /// generate offers
            for (int i = 0; i < numOffers; i++)
            {
                registerMyOffer(offers[i], std::to_string(i + 1) + ".");
            }
            print_debug("Registration of FHE offers ok");

            /// decipher AES layer and store FHE offers
            vector<LweSample *> clearedOffers;
            for (int i = 0; i < numOffers; i++)
            {
                clearedOffers = utils_decryptOffer(std::to_string(i + 1) + ".", numOffers, clearedOffers);
            }
            print_debug("Decipher of FHE offers ok (#=" + std::to_string(clearedOffers.size()) + ")");

            //  launch comparison on "clearedOffers" that contains the cipher of all offers,
            print_debug("Launching comparison");
            utils_compare(clearedOffers, numOffers);

            //  decipher argmax for verification
            utils_decipherArgmax(clearedOffers.size());

            message.reply(status_codes::OK, "OK- debug");
        }
        catch (const std::exception &e)
        {
            cout << "[ERROR] --> in debug multi" << endl;
            std::cerr << e.what() << std::endl;
        }
    }

    else
    {
        message.reply(status_codes::InternalError, "Unknow path");
    }
    // message.reply(status_codes::OK, message.to_string());
    return;
};
