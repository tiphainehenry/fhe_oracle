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
#include "./Verif.cc"
#include "./Hasher.cc"
#include "./Cloud.cc"
using namespace CryptoPP;
using aes_key_t = std::array<byte, CryptoPP::AES::DEFAULT_KEYLENGTH>;
using aes_iv_t = std::array<byte, CryptoPP::AES::BLOCKSIZE>;



void provider(int nbr_offers, char *av[])
{
    aes_iv_t iv{};
    CryptoPP::AutoSeededRandomPool AESrng{};
    AESrng.GenerateBlock(iv.data(), iv.size());
    CryptoPP::ArraySource as(iv.data(), iv.size(), true, new CryptoPP::FileSink("newIV.data"));

    uint32_t seed[] = {314, 1592, 657};
    Hasher hasher = Hasher(100, seed);
    std::vector<LweSample *> cipher;
    for (size_t i = 1; i < nbr_offers; i++)
    {
        cipher.push_back(hasher.cipherInt(atoi(av[i])));
    }

    hasher.exportKey();
    hasher.exportCloudKey();
    hasher.export2Data(cipher, "cloud.data");
    aes_key_t key = hasher.generateAESKey("AES.key");
    hasher.encrypt(key, iv, "cloud.data", "AES.data");
}

void new_offer(int value, string RSAfilename)
{
    aes_iv_t iv{};
    CryptoPP::AutoSeededRandomPool AESrng{};
    AESrng.GenerateBlock(iv.data(), iv.size());
    CryptoPP::ArraySource as(iv.data(), iv.size(), true, new CryptoPP::FileSink("newIV.data"));

    uint32_t seed[] = {314, 1592, 657};
    Hasher hasher = Hasher(100, seed);
    std::vector<LweSample *> cipher;
    cipher.push_back(hasher.cipherInt(value));

    hasher.exportKey();
    hasher.exportCloudKey();
    hasher.export2Data(cipher, "cloud.data");
    aes_key_t key = hasher.generateAESKey("AES.key", RSAfilename);
    hasher.encrypt(key, iv, "cloud.data", "AES.data");
}

void new_project()
{
    uint32_t seed[] = {314, 1592, 657};
    Hasher hasher = Hasher(100, seed);
    hasher.generateRSAKey();
    hasher.exportKey();
    hasher.exportCloudKey();
}

void comparator(int ac, char *av[])
{
    aes_iv_t iv{};
    CryptoPP::FileSource fs("newIV.data", true, new CryptoPP::ArraySink(iv.data(), iv.size()));

    uint32_t seed[] = {314, 1592, 657};
    Hasher hasher = Hasher(100, seed);
    std::Cloud cloud = std::Cloud("cloud.data", ac - 1, hasher.cipherInt(0), hasher.cipherInt(10));
    cloud.RSADecryption("tt");
    aes_key_t key2 = cloud.getAESKey("AES2.key");
    cloud.decrypt(key2, iv, "AES.data", "cloud.data");
    cloud.getCipher("cloud.data");
    std::clock_t start;
    start = std::clock();
    cloud.getMinimum();
    std::cout << "Time: " << (std::clock() - start) / (double)(CLOCKS_PER_SEC / 1000) << " ms" << std::endl;
}

int main(int ac, char *av[])
{
    provider(ac, av);
    comparator(ac, av);
    std::Verif verifz = std::Verif(ac - 1);
    verifz.decrypt("answer.data");
    return (0);
}