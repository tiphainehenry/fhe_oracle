RestHash
========
This repo comprises the code used to generate a REST API that allows:
- tender generation
- RSA, FHE, and AES key initialization 
- the generation of ciphered offers (AES, RSA, and FHE combination)
- the comparison of ciphered offers. 

Code is written in CPP. 


Install
-------
Requirements:

* [TFHE](http://tfhe.github.io/tfhe/installation.html)

* [CRYPTOpp](https://www.cryptopp.com/wiki/Linux#Distribution_Package -- an issue may occur with ++ instead of pp)

* [IPFS](https://github.com/vasild/cpp-ipfs-http-client) (only if IPFS config is set to local)

* [CPPRestSDK](https://github.com/microsoft/cpprestsdk/wiki/How-to-build-for-Linux)

* [Nlohmann]

* [boost] (https://www.boost.org/doc/libs/1_61_0/more/getting_started/unix-variants.html)

Compiling and launching the API server
--------------------------------------

Adapt API configuration: 
* IPFS: 
    * set ipfs configuration in RestHash/src/utils/url_filenames.json: ipfs_config can be "local" or "infura".
    * If local config: launch ipfs daemon (running on http://localhost:5001) with the command `ipfs daemon`.
* Paths: 
    * Adapt the pathes to your machine in (1) src/utils/utils.cpp and (2) src/utils/url_filenames.json: 

Compile and launch the server: 
* `./comp.sh`
* The server runs on http://127.0.0.1:34568.

(alternatively):
`g++ -std=c++11 src/*.cc src/handler.cpp -o server -lboost_system -lcrypto -lssl -lcpprest -pthread -lipfs-http-client -lcurl -ltfhe-spqlios-fma -lstdc++ -lcrypto++

./server`

REST Commands: Curl requests
----------------------------
__Tender creation__ `curl -d "a=b"  http://localhost:34568/newTender?Hash=test`

* Creation of a new tender where Hash is the value of the new IPFS Hash where the offer will be stored. (for demo, we suppose hash=test)
* generation of FHE and RSA keys 

__Register a new offer__ `curl -v POST http://localhost:34568/offer?offer=2323 -d @test.json --header "Content-Type: application/json"`

The user specifies the value (eg 2323) and the tender name (eg test.json).

* Generation of own AES key
* Cipher the offer with FHE and AES.
* Cipher the AES key with RSA 
* The ciphered value is appended to test.json

__Launch a comparison__ `curl -v POST  http://localhost:34568/findBestOffer -d @test.json --header "Content-Type: application/json"`

* Send the ciphered offer with the JSON "test.json"

__Local debug on X offers__  `curl -d "a=b"  http://localhost:34568/debug/n=X`

