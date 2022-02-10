This repo comprises the code used to generate an API that allows:
- tender generation
- RSA, FHE, and AES key initialization 
- the generation of ciphered offers (AES, RSA, and FHE combination)
- the comparison of ciphered offers. 
Code is written in CPP. 

RestHash
========
Rest API using Hashcompare

Install
-------
Requirements:

* [TFHE](http://tfhe.github.io/tfhe/installation.html)

* [CRYPTOpp](https://www.cryptopp.com/wiki/Linux#Distribution_Package -- an issue may occur with ++ instead of pp)

* [IPFS](https://github.com/vasild/cpp-ipfs-http-client)

* [CPPRestSDK](https://github.com/microsoft/cpprestsdk/wiki/How-to-build-for-Linux)

* [Nlohmann]

* [boost] (https://www.boost.org/doc/libs/1_61_0/more/getting_started/unix-variants.html)

Compiling
---------
    $./comp.sh

Smart Contract
====
[Work in progress]
---

* Oracle.sol
    - oracle using provable to access to a public API and stocking the value
* TenderManager.sol
    - Smart contract managing Tenders and offers. each struct contain the IPFS link to their respectives data.

Usage
---

Compile and test via [Remix](https://remix.ethereum.org/#version=soljson-v0.5.16+commit.9c3226ce.js&optimize=false&evmVersion=null&gist=8a28f5ee239b7815b935d883f1239904&runs=200).


# Commands

### step0: BEFORE compilation:
-->> in (1) src/utils/utils.cpp and (2) src/utils/url_filenames.json: adapt the pathes to your machine

### step1: launch API server (running on http://127.0.0.1:34568): 
`./comp.sh`

(alternatively):

`g++ -std=c++11 src/*.cc src/handler.cpp -o server -lboost_system -lcrypto -lssl -lcpprest -pthread -lipfs-http-client -lcurl -ltfhe-spqlios-fma -lstdc++ -lcrypto++
./server`

### step2: IPFS:
(1) set ipfs configuration in RestHash/src/utils/url_filenames.json: ipfs_config can be "local" or "infura".
(2) if ipfs_config is set to "local", then, before launching the API, launch ipfs daemon (running on http://localhost:5001) with the command "ipfs daemon.

### step3: Curl requests:
#### Creation of a new tender where Hash is the value of the new IPFS Hash where the offer will be stored. (for demo, we suppose hash=test)  >> generation of FHE and RSA keys 
`curl -d "a=b"  http://localhost:34568/newTender?Hash=test`

#### NEW OFFER:
#### 1) Cipher the offer. The user specifies the value. Here value=2323. The ciphered value is appended to test.json >> generation of own AES key
`curl -v POST http://localhost:34568/offer?offer=2323 -d @test.json --header "Content-Type: application/json"`

#### 2) Send the ciphered offer with the JSON "test.json"
`curl -v POST  http://localhost:34568/findBestOffer -d @test.json --header "Content-Type: application/json"`

#### 3) Local debug on X offers:
`curl -d "a=b"  http://localhost:34568/debug/n=X`

