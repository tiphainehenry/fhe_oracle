#### COMMANDS

#step1: launch API server (running on http://127.0.0.1:34568): 
./comp.sh

#(alternatively): 
g++ -std=c++11 src/*.cc src/handler.cpp -o server -lboost_system -lcrypto -lssl -lcpprest -pthread -lipfs-http-client -lcurl -ltfhe-spqlios-fma -lstdc++ -lcrypto++

./server

#step2: launch ipfs daemon (running on http://localhost:5001): 
ipfs daemon 


#step3: Curl requests:
# Creation of a new tender where Hash is the value of the new IPFS Hash where the offer will be stored. (for demo, we suppose hash=test) 
curl -d "a=b"  http://localhost:34568/newTender?Hash=test

# NEW OFFER:
## Cipher the offer. The user specifies the value. Here value=2323. The ciphered value is appended to test.json
curl -d "a=v" http://localhost:34568/offer?offer=2323

## Send the ciphered offer with the JSON "test.json"
curl -v POST  http://localhost:34568/findBestOffer -d @test.json --header "Content-Type: application/json"

## Local debug:
curl -d "a=b"  http://localhost:34568/debugOfferMulti

