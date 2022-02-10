#!/bin/bash

g++ src/*.cc  src/createKeys.cpp -o createKeys.out -lboost_system -lcrypto -lssl -lcpprest -pthread -lipfs-http-client -lcurl -ltfhe-spqlios-fma -lstdc++ -lcryptopp
./createKeys.out