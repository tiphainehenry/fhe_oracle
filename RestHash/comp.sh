#!/bin/bash
if [ "$1" == "clean" ];
then
    rm server||:	
    rm .tmp/*.data .tmp/*.key .tmp/*.metadata ||: 
fi
g++ src/*.cc  src/handler.cpp -o server -lboost_system -lcrypto -lssl -lcpprest -pthread -lipfs-http-client -lcurl -ltfhe-spqlios-fma -lstdc++ -lcryptopp
./server
