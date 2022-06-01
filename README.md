# fhe_oracle


This repo comprises the code used to generate a REST API that allows:

- tender generation
- RSA, FHE, and AES key initialization
- the generation of ciphered offers (AES, RSA, and FHE combination)
- the comparison of ciphered offers.

Code is written in CPP.

## Install


Requirements:

- libcurl, version 7.25.0 or higher
- C++11 compiler
- CMake, version 3.11.0 or higher
- [TFHE](http://tfhe.github.io/tfhe/installation.html)
- [CRYPTOpp](https://www.cryptopp.com/wiki/Linux#Distribution_Package) - NB: an issue may occur with ++ instead of pp
- [IPFS](https://github.com/vasild/cpp-ipfs-http-client)
- [CPPRestSDK](https://github.com/microsoft/cpprestsdk/wiki/How-to-build-for-Linux)
- [boost](https://www.boost.org/doc/libs/1_61_0/more/getting_started/unix-variants.html)
- [Nlohmann] json

## Compiling and launching the API server


IPFS configuration:

- Case Infura:
  - set ipfs_config to "infura" in src/utils/url_filenames.json.
- Case Local:
  - set ipfs_config to "local" in src/utils/url_filenames.json.
  - launch `ipfs daemon` (running on http://localhost:5001)

Compile and launch the server:

- To launch the server that runs on http://127.0.0.1:34568, there are two possibilities:

  - `./comp.sh`
  - `./comp.sh clean` for a clean environment: it empties the /tmp folder, removes ciphering keys, and resets the test.json file.

- Alternative manual compilation:
  - `g++ -std=c++11 src/*.cc src/handler.cpp -o server -lboost_system -lcrypto -lssl -lcpprest -pthread -lipfs-http-client -lcurl -ltfhe-spqlios-fma -lstdc++ -lcrypto++`
  - `./server`

## REST Commands: Curl requests


**Tender creation** `curl -d "a=b" http://localhost:34568/newTender?Hash=test`

- Creation of a new tender where Hash is the value of the new IPFS Hash where the offer will be stored. (for demo, we suppose hash=test)
- generation of FHE and RSA keys

**Register a new offer** `curl -v POST http://localhost:34568/offer?offer=2323 -d @test.json --header "Content-Type: application/json"`

The user specifies the value (eg 2323) and the tender name (eg test.json).

- Generation of own AES key
- Cipher the offer with FHE and AES.
- Cipher the AES key with RSA
- The ciphered value is appended to test.json

**Launch a comparison** `curl -v POST http://localhost:34568/findBestOffer -d @test.json --header "Content-Type: application/json"`

- Send the ciphered offer with the JSON "test.json"

**Local debug on X offers** `curl -d "a=b" http://localhost:34568/debug/n=X`

**Local addition on X offers** `curl -d "a=b" http://localhost:34568/finddebugaddition/n=X`

**Local substraction on X offers** `curl -d "a=b" http://localhost:34568/finddebugsubstraction/n=X`
