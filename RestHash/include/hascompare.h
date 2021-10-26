#pragma once
#ifndef HASHCOMPARE_H
#define HASHCOMPARE_H
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>
#include <iostream>
#include <ctime>
#include <iomanip>
#include <cryptopp/modes.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/rsa.h>
#include "../Verif.cc"
#include "../Hasher.cc"
// #include "../RSAToTFHE.cc"
// #include "../Cloud.cc"
using namespace CryptoPP;


using aes_key_t = std::array<byte, CryptoPP::AES::DEFAULT_KEYLENGTH>;
using aes_iv_t = std::array<byte, CryptoPP::AES::BLOCKSIZE>;

void full_adder(LweSample*, LweSample const*, LweSample const*, int, TFheGateBootstrappingCloudKeySet const*);
void new_project();
void new_offer(int, string, string);
void compare(int);
void decipherArgmax(int);

LweSample *decryptOffer(string , string);

#endif // !HASHCOMPARE_H(HASHCOMPARE_H)
