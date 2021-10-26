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
        new_offer(atoi(offer.c_str()), "publicKey.key", prefix);

        /// storage of new offer into ipfs
        client.FilesAdd(
            {{"AES.key", ipfs::http::FileUpload::Type::kFileName, ".tmp/" + prefix + "AES.key"},
             {"AES.data", ipfs::http::FileUpload::Type::kFileName, ".tmp/" + prefix + "AES.data"}},
            &tmp);
        // remove("AES.key");
        // remove("AES.data");

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
    else if (message.relative_uri().path() == "/debugOfferOne")
    {
        try{

            string offers[3] = {"10"};
            vector<LweSample *> clearedOffersOne;
            string RSAfilename="publicKey.key";

            Json tmp = {};
            //************************************************************//
            //************************************************************//
            std::cout << "[DEBUG] Test with 1 offer -test" << endl;

            // GENERATE OFFERS
            string prefix="1.";            
            std::string AESKeyName1 = ".tmp/1.AES.key";
            std::string offerName1 = ".tmp/1.AES.data";

            cipherOfferWithFHE(prefix, offers[0]);  // RETRIEVE FHE DATA AND CIPHER OFFER IN FHE
            addAESLayer(prefix, RSAfilename);             // CIPHER AES KEY IN RSA            

            //************************************************************//
            /// decipher AES layer and store FHE offers
            int numOffers = 1;

            LweSample* cloud_ciphertext = utils_decryptOffer(prefix, numOffers);
            clearedOffersOne.push_back(cloud_ciphertext);

            //print_info_3m("FHE offer appended (offers size=", clearedOffersOne.size(), ")")
            
            message.reply(status_codes::OK, "OK- debug");

        }
        catch (const std::exception &e)
        {
            cout << "[ERROR] --> in debug one" << endl;
            std::cerr << e.what() << std::endl;
        }
    }

    else if (message.relative_uri().path() == "/debugOfferMulti")
    {
        try{

            string offers[3] = {"1000","62","340"};
            vector<LweSample *> clearedOffers;

            Json tmp = {};
            //************************************************************//
            //************************************************************//
            
            print_debug("Test with 3 offers");
 
            string prefix1 = "1.";
            string prefix2 = "2.";
            string prefix3 = "3.";

            /// generate offers            
            registerMyOffer(offers[0], prefix1);
            registerMyOffer(offers[1], prefix2);
            registerMyOffer(offers[2], prefix3);

            //************************************************************//
            int numOffers_debug = sizeof(offers)/sizeof(offers[0]);
            print_debug(std::to_string(numOffers_debug));


            int numOffers = 3;

            /// decipher AES layer and store FHE offers
            LweSample* cloud_ciphertext1 = utils_decryptOffer(prefix1, numOffers);
            clearedOffers.push_back(cloud_ciphertext1);

            LweSample* cloud_ciphertext2 = utils_decryptOffer(prefix2, numOffers);
            clearedOffers.push_back(cloud_ciphertext2);

            LweSample* cloud_ciphertext3 = utils_decryptOffer(prefix3, numOffers);
            clearedOffers.push_back(cloud_ciphertext3);

            print_debug(std::to_string(clearedOffers.size()) + " FHE offer appended)");

            //************************************************************//
            //  "clearedOffers" contains the cipher of all offers,
            //  we need tu use the function of the Comparator class to compare offers and retrieve the best offer.

            print_debug("Lauching comparison"); 
            
            utils_compare(clearedOffers, numOffers);
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
