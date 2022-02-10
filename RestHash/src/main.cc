#include <iostream>
#include <sstream>

#include <ipfs/client.h>
#include "include/stdafx.h"
#include "include/handler.h"

using namespace std;
using namespace web;
using namespace http;
using namespace utility;
using namespace http::experimental::listener;
using Json = nlohmann::json;

std::unique_ptr<handler> g_httpHandler;

std::string url="/home/vtlr2002/source/HashCompare/RestHash/src/utils/url_filenames.json";
string get_ipfs_config_main(){
    std::ifstream ifs(url);
    Json jf = Json::parse(ifs);
    std::string ipfsConfig= jf["ipfs_config"];
    return ipfsConfig;
}


void on_initialize(const string_t &address)
{
    uri_builder uri(address);

    auto addr = uri.to_uri().to_string();
    g_httpHandler = std::unique_ptr<handler>(new handler(addr));
    g_httpHandler->open().wait();

    ucout << utility::string_t(U("Listening for requests at: ")) << addr << std::endl;

    return;
}

void on_shutdown()
{
    g_httpHandler->close().wait();
    return;
}

#ifdef _WIN32
int wmain(int argc, wchar_t *argv[])
#else
int main(int argc, char *argv[])
#endif
{
    std::stringstream contents;
    ipfs::Json tmp;
    // Configure IPFS
    std::string ipfsConfig = get_ipfs_config_main();
    
    ipfs::Client client("ipfs.infura.io", 5001, "20s", "https://");
    if (ipfsConfig == "local") {        
        ipfs::Client client("localhost", 5001);
        std::cout<< "IPFS config = local"<<std::endl;

    } else if(ipfsConfig == "infura"){
        ipfs::Client client("ipfs.infura.io", 5001, "20s", "https://");
        std::cout<< "IPFS config = infura"<<std::endl;
    }
    else{
        std::cout<< "IPFS config not recognized"<<std::endl;
        on_shutdown();
        return 0;
    }

    // Launch ports
    utility::string_t port = U("34568");
    utility::string_t address = U("http://127.0.0.1:");
    address.append(port);

    on_initialize(address);
    std::cout << "Press ENTER to exit." << std::endl;

    std::string line;
    std::getline(std::cin, line);

    on_shutdown();
    return 0;
}
