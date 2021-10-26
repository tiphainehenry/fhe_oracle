#!/bin/bash
rm main
rm *.data *.key *.o *.out

if [ $1 = "clean" ]
then
    exit
fi
make
./main 12 898 12 1