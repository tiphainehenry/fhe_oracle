#!/bin/bash
if [ $1 != "keep" ];
then
    rm main
    rm *.data *.key *.o *.out *.offer *.metadata
fi
if [ $1 == "clean" ];
then
    exit
fi
g++   *.cc  src/handler.cpp -o server -lboost_system -lcrypto -lssl -lcpprest -pthread -lipfs-http-client -lcurl -ltfhe-spqlios-fma -lstdc++ -lcryptopp
./server
