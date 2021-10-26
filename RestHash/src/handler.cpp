#include <ipfs/client.h>
#include <boost/algorithm/string.hpp>
#include <iostream>
#include <nlohmann/json.hpp>
#include <sstream>
#include <stdexcept>
#include "../include/handler.h"
#include "../include/hascompare.h"
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
    //ucout << '1' << ". path msg. " << message.relative_uri().path() << endl;
    //ucout << '2' << ". query msg." << message.relative_uri().query() << endl;
    auto queries = uri::split_query(message.relative_uri().query());

    if (message.relative_uri().path() == "/newTender")
    {
        std::cout << "[INFO] Creating new tender - test modif" << endl;

        //create a new Tender
        if (queries.find("Hash") == queries.end())
        {
            message.reply(status_codes::InternalError, "No Hash provided");
        }
        else
        {

            try
            {
                //************************************************************************************************//
                //************************************************************************************************//
                //FHE KEYS
                //************************************************************************************************//
                //************************************************************************************************//
                cout << "FHE KEYS " << endl;

                //STEP 1:GENERATE AND STORE PARAMS
                
                //generate params
                const int minimum_lambda = 110;
                TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(minimum_lambda);
                // export the parameter to file for later use
                FILE* params_file = fopen(".tmp/params.metadata","wb");
                export_tfheGateBootstrappingParameterSet_toFile(params_file, params);
                fclose(params_file);

                //**************//
                //STEP 2: GENERATE AND STORE FHE KEYSET
                //generate a random key
                uint32_t seed[] = { 314, 1592, 657 };
                tfhe_random_generator_setSeed(seed,3);
                TFheGateBootstrappingSecretKeySet* key = new_random_gate_bootstrapping_secret_keyset(params);

                //export the secret key to file for later use
                FILE* secret_key = fopen(".tmp/secret.key","wb");
                export_tfheGateBootstrappingSecretKeySet_toFile(secret_key, key);
                fclose(secret_key);

                //export the cloud key to a file (for the cloud)
                FILE* cloud_key = fopen(".tmp/cloud.key","wb");
                export_tfheGateBootstrappingCloudKeySet_toFile(cloud_key, &key->cloud);
                fclose(cloud_key);
            

                //**************//
                //clean up all pointers
                delete_gate_bootstrapping_secret_keyset(key);
                delete_gate_bootstrapping_parameters(params);

                //************************************************************************************************//
                //************************************************************************************************//
                //RSA KEYS
                //************************************************************************************************//
                //************************************************************************************************//
                cout << "RSA KEYS " << endl;
                utils_generateRSAKey();
                
                //************************************************************************************************//
                //************************************************************************************************//
                //IPFS STORAGE 
                //************************************************************************************************//
                //************************************************************************************************//
                cout << "IPFS STORAGE " << endl;
                ipfs::Json tmp;
                ipfs::Client client("localhost", 5001);
                string response;
                                
                client.FilesAdd({{"publicKey.key", ipfs::http::FileUpload::Type::kFileName, "/home/vtlr2002/source/HashCompare/RestHash/.tmp/publicKey.key"},
                                 {"secret.key", ipfs::http::FileUpload::Type::kFileName, "/home/vtlr2002/source/HashCompare/RestHash/.tmp/secret.key"},
                                 {"cloud.key", ipfs::http::FileUpload::Type::kFileName, "/home/vtlr2002/source/HashCompare/RestHash/.tmp/cloud.key"},
                                 {"params.metadata", ipfs::http::FileUpload::Type::kFileName, "/home/vtlr2002/source/HashCompare/RestHash/.tmp/params.metadata"}
                                 },
                                &tmp);


                string keyTypeShort [4]= {
                    "(RSA public key to cipher AES keys)",
                    "(FHE private key to cipher clear offers)",
                    "(FHE public key for oracle ciphered comparisons)",
                    "(FHE params metadata used to process ciphers)"
                    };

                for (size_t i = 0; i < tmp.size(); i++)
                {
                    cout << "==> " << tmp[i]["hash"] << keyTypeShort[i] << endl;
                    response = response + tmp[i]["hash"].dump() + keyTypeShort[i] + "/n";
                }

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
            std::cout << "[INFO] Find best offer" << endl;

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
                std::cout << "[INFO] Deciphering Offer n°" << it->first << "\n";
                std::cout << "(KEY: " << key << "|OFFER:" << offer << ")" << endl;

                // Retrieve key and offer IPFS data and save it locally
                std::string keyFileName = utils_ipfsToFile(key, it->first, client, "key");
                std::string offerFileName = utils_ipfsToFile(offer, it->first, client, "offer");
                cout << "[INFO] Offer IPFS data succesfully retrieved (AES key+ AES/FHE ciphered offer)" << endl;
                // decipher AES layer and store FHE offer in the "offers" vector
                offers.push_back(decryptOffer(keyFileName, offerFileName));
                cout << "[INFO] FHE offer appended (offers size=" << offers.size() << ")" << endl;
            }

            std::cout << "_______________________________________________________"
                      << "\n";
            cout << "[TODO] Compare offers" << endl;
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
            int value=atoi(offers[0].c_str());
            string prefix="1.";            
            std::string AESKeyName1 = ".tmp/1.AES.key";
            std::string offerName1 = ".tmp/1.AES.data";

            cipherOfferWithFHE(prefix, value);  // RETRIEVE FHE DATA AND CIPHER OFFER IN FHE
            addAESLayer(prefix, RSAfilename);             // CIPHER AES KEY IN RSA            

            //************************************************************//
            /// decipher AES layer and store FHE offers
            int numOffers = 1;

            LweSample* cloud_ciphertext = utils_decryptOffer(prefix, AESKeyName1, offerName1, numOffers);
            clearedOffersOne.push_back(cloud_ciphertext);
            std::cout << "[INFO] FHE offer appended (offers size=" << clearedOffersOne.size() << ")" << endl;

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
            string RSAfilename=".tmp/publicKey.key";

            Json tmp = {};
            //************************************************************//
            //************************************************************//
            
            std::cout << "[DEBUG] Test with 3 offers" << endl;
            /// generate offers
            
            int value1=atoi(offers[0].c_str());
            string prefix1="1.";            
            std::string AESKeyName1 = ".tmp/1.AES.key";
            std::string offerName1 = ".tmp/1.AES.data";

            cipherOfferWithFHE(prefix1, value1);  // RETRIEVE FHE DATA AND CIPHER OFFER IN FHE
            addAESLayer(prefix1, RSAfilename);             // CIPHER AES KEY IN RSA            


            int value2=atoi(offers[1].c_str());
            string prefix2="2.";            
            std::string AESKeyName2 = ".tmp/2.AES.key";
            std::string offerName2 = ".tmp/2.AES.data";

            cipherOfferWithFHE(prefix2, value2);  // RETRIEVE FHE DATA AND CIPHER OFFER IN FHE
            addAESLayer(prefix2, RSAfilename);             // CIPHER AES KEY IN RSA            


            int value3=atoi(offers[2].c_str());
            string prefix3="3.";            
            std::string AESKeyName3 = ".tmp/3.AES.key";
            std::string offerName3 = ".tmp/3.AES.data";

            cipherOfferWithFHE(prefix3, value3);  // RETRIEVE FHE DATA AND CIPHER OFFER IN FHE
            addAESLayer(prefix3, RSAfilename);             // CIPHER AES KEY IN RSA            

            //************************************************************//

            //int numOffers = sizeof(offers)/sizeof(offers[0]);
            int numOffers = 3;

            /// decipher AES layer and store FHE offers
            LweSample* cloud_ciphertext1 = utils_decryptOffer(prefix1, AESKeyName1, offerName1, numOffers);
            clearedOffers.push_back(cloud_ciphertext1);

            LweSample* cloud_ciphertext2 = utils_decryptOffer(prefix2, AESKeyName2, offerName2, numOffers);
            clearedOffers.push_back(cloud_ciphertext2);

            LweSample* cloud_ciphertext3 = utils_decryptOffer(prefix3, AESKeyName3, offerName3, numOffers);
            clearedOffers.push_back(cloud_ciphertext3);

            std::cout << "[INFO] FHE offer appended (offers size=" << clearedOffers.size() << ")" << endl;
            std::cout << "_______________________________________________________"
                      << "\n";
            cout << "[INFO] Lauching comparison" << endl;
            //  "offers" contains the cipher of all offers,
            //  we need tu use the function of the Comparator class to compare offers and retrieve the best offer.

            //int numOffers = 3;
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
