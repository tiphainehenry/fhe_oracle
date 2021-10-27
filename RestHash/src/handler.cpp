#include <ipfs/client.h>
#include <boost/algorithm/string.hpp>
#include <iostream>
#include <nlohmann/json.hpp>
#include <sstream>
#include <stdexcept>
#include "../include/handler.h"
//#include "../RSAToTFHE.cc"
//#include "../Cloud.cc"
#include "utils.cpp"
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

                // ipfs storage
                string path_to_tmp = "/home/vtlr2002/source/HashCompare/RestHash/.tmp/";
                string response = store_keys_to_ipfs(path_to_tmp);
                message.reply(status_codes::OK, response);
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

            ipfs::Client client("localhost", 5001);
            vector<string> offerNames;
            vector<LweSample *> offers;
            auto tmp = message.extract_json().get();                                     // reading test.json data stored as tmp
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
                std::cout << "(KEY: " << key << "|OFFER:" << offer << ")" << endl;

                // Retrieve key and offer IPFS data and save it locally
                std::string keyFileName = utils_ipfsToFile(key, it->first, client, "key");
                std::string offerFileName = utils_ipfsToFile(offer, it->first, client, "offer");
                print_info("Offer IPFS data succesfully retrieved (AES key+ AES/FHE ciphered offer)");
                // decipher AES layer and store FHE offer in the "offers" vector
                offers.push_back(decryptOffer(keyFileName, offerFileName));
                cout << "[INFO] FHE offer appended (offers size=" << offers.size() << ")" << endl;
            }

            std::cout << "_______________________________________________________"
                      << "\n";

            print_info("Compare offers");
            //  "offers" contains the cipher of all offers,
            //  we need tu use the function of the Comparator class to compare offers and retrieve the best offer.

            //compare(offers.size());
            //decipherArgmax(offers.size());

            message.reply(status_codes::OK, "Best offer is ... ");
        }

        catch (const std::exception &e)
        {
            cout << "[ERROR] --> in find best offer" << endl;
            std::cerr << e.what() << std::endl;
        }
    }
    else if (message.relative_uri().path() == "/offer")
    {
        try{
        ipfs::Client client("localhost", 5001);
        ipfs::Json tmp;
        string offer = queries["offer"];

        /// cloud data prefix computation
        
        std::string prefix = utils_computeNumberOfOffers(message);

        /// computation of the new offer (ciphered data and aes key)
        //registerMyOffer(offer, prefix);

        /// storage of new offer into ipfs
        //client.FilesAdd(
        //    {{"AES.key", ipfs::http::FileUpload::Type::kFileName, ".tmp/" + prefix + "AES.key"},
        //     {"AES.data", ipfs::http::FileUpload::Type::kFileName, ".tmp/" + prefix + "AES.data"}},
        //    &tmp);

        // TODO: add elem to test.json !        
        //std::ifstream ifs("test.json");
        //Json j = json::parse(ifs);

        message.reply(status_codes::OK, "OK- Offer created");

        }
        catch (const std::exception &e)
        {
            cout << "[ERROR] --> in new offer" << endl;
            std::cerr << e.what() << std::endl;
        }
    }

    else if (message.relative_uri().path() == "/debug")
    {
        try{

            print_debug("Launching test with 3 offers");                                     
            int numOffers = 3; 
            string offers[numOffers] = {"1000","62","340"};

            /// generate offers
            for (int i = 0; i < numOffers; i++)
            {
                registerMyOffer(offers[i], std::to_string(i+1)+".");
            }
            print_debug("Registration of FHE offers ok");

            /// decipher AES layer and store FHE offers
            vector<LweSample *> clearedOffers;
            for (int i = 0; i < numOffers; i++)
            {
                clearedOffers = utils_decryptOffer(std::to_string(i+1)+".", numOffers, clearedOffers); 
            }
            print_debug("Decipher of FHE offers ok (#="+std::to_string(clearedOffers.size())+")");

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
