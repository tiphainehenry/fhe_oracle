# COMMANDS

## step0: BEFORE compilation:
-->> in (1) src/utils/utils.cpp and (2) src/utils/url_filenames.json: adapt the pathes to your machine

## step1: launch API server (running on http://127.0.0.1:34568): 
./comp.sh

(alternatively): 
g++ -std=c++11 src/*.cc src/handler.cpp -o server -lboost_system -lcrypto -lssl -lcpprest -pthread -lipfs-http-client -lcurl -ltfhe-spqlios-fma -lstdc++ -lcrypto++
./server

## step2: IPFS:
(1) set ipfs configuration in RestHash/src/utils/url_filenames.json: ipfs_config can be "local" or "infura".
(2) if ipfs_config is set to "local", then, before launching the API, launch ipfs daemon (running on http://localhost:5001) with the command "ipfs daemon.

## step3: Curl requests:
# Creation of a new tender where Hash is the value of the new IPFS Hash where the offer will be stored. (for demo, we suppose hash=test) 
# >> generation of FHE and RSA keys 
curl -d "a=b"  http://localhost:34568/newTender?Hash=test

# NEW OFFER:
# 1) Cipher the offer. The user specifies the value. Here value=2323. The ciphered value is appended to test.json
# >> generation of own AES key
curl -v POST http://localhost:34568/offer?offer=2323 -d @test.json --header "Content-Type: application/json"

# 2) Send the ciphered offer with the JSON "test.json"
curl -v POST  http://localhost:34568/findBestOffer -d @test.json --header "Content-Type: application/json"

# 3) Local debug on X offers:
curl -d "a=b"  http://localhost:34568/debug/n=X

