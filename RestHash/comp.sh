#!/bin/bash
if [ $1 != "keep" ];
then
    rm server	
    rm .tmp/*.data .tmp/*.key .tmp/*.metadata 
fi
if [ $1 == "clean" ];
then
    exit
fi
g++ src/*.cc  src/handler.cpp -o server -lboost_system -lcrypto -lssl -lcpprest -pthread -lipfs-http-client -lcurl -ltfhe-spqlios-fma -lstdc++ -lcryptopp
./server
