#include <tfhe/tfhe.h>
#include <iostream>
#include <cryptopp/modes.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>
#include <time.h>
#include "./test-addition-boot.cc"

namespace std
{
    class Cloud
    {
    private:
        TFheGateBootstrappingCloudKeySet *cloudKey;
        vector<LweSample *> ciphertext1;
        vector<int> clear = {123, 456, 789};
        // vector<vector<int>> rez;
        int offersNbr;
        // vector<vector<LweSample *>> result;
        vector<LweSample *> ciphertext2;
        LweSample *zero;
        LweSample *one;

    public:
        Cloud(string fileName, int nbr, LweSample *Zero, LweSample *One)
        {
            cout << "cloud cons \n"; 
            offersNbr = nbr;
            zero = Zero;
            one = One;
            FILE *ck = fopen("cloud.key", "rb");
            cloudKey = new_tfheGateBootstrappingCloudKeySet_fromFile(ck);
            fclose(ck);
            for (size_t i = 0; i < offersNbr; i++)
            {
                ciphertext1.push_back(new_gate_bootstrapping_ciphertext_array(16, cloudKey->params));
                ciphertext2.push_back(new_gate_bootstrapping_ciphertext_array(16, cloudKey->params));
            }
            cout << "cloud cons end\n"; 

        }
        ~Cloud() {}
        /***
 * 
 * */

        void decrypt(const aes_key_t &key, const aes_iv_t &iv,
                     const std::string &filename_in, const std::string &filename_out)
        {
            CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption cipher{};
            cipher.SetKeyWithIV(key.data(), key.size(), iv.data());

            std::ifstream in{filename_in, std::ios::binary};
            std::ofstream out{filename_out, std::ios::binary};

            CryptoPP::FileSource{in, /*pumpAll=*/true,
                                 new CryptoPP::StreamTransformationFilter{
                                     cipher, new CryptoPP::FileSink{out}}};
        }
        void RSADecryption(string filename)
        {
            CryptoPP::AutoSeededRandomPool rng;
            RSAES_OAEP_SHA_Decryptor dec;
            dec.AccessKey().BERDecode(FileSource("privateKey.key", true).Ref());

            std::ifstream in{"AES.key", std::ios::binary};
            CryptoPP::FileSource ss2("AES.key", true,
                                     new PK_DecryptorFilter(rng, dec,
                                                            new FileSink("AES2.key")) // PK_DecryptorFilter
            );                                                                        // StringSource
        }
        aes_key_t getAESKey(string filename)
        {
            aes_key_t key;
            CryptoPP::FileSource fs(filename.c_str(), true, new CryptoPP::ArraySink(key.data(), key.size()));
            return key;
        }

        void getCipher(string fileName)
        {
            FILE *cloud_data = fopen(fileName.c_str(), "rb");
            cout << "opened cloud \n";
            for (size_t j = 0; j < offersNbr; j++)
            {
                cout << j << endl;
                for (int i = 0; i < 16; i++)
                {
                    import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertext1[j][i], cloudKey->params);
                }
            }
            fclose(cloud_data);
            cout << "closed cloud \n";

        }

        void compare_bit(LweSample *result, const LweSample *a, const LweSample *b, const LweSample *lsb_carry, LweSample *tmp, const TFheGateBootstrappingCloudKeySet *bk)
        {
            bootsXNOR(tmp, a, b, bk);
            bootsMUX(result, tmp, lsb_carry, a, bk);
        }

        LweSample *addition(const LweSample *a, const LweSample *b)
        {
            LweSample *res = new_gate_bootstrapping_ciphertext_array(16, cloudKey->params);
            LweSample *tt = new_gate_bootstrapping_ciphertext_array(16, cloudKey->params);
            full_adder(res, a, b, 16, cloudKey);

            FILE *answer_data = fopen("answer.data", "wb");
            for (int i = 0; i < 16; i++)
            {
                export_gate_bootstrapping_ciphertext_toFile(answer_data, &res[i], cloudKey->params);
            }
            fclose(answer_data);
            return (res);
        }

        // LweSample   *substract(const LweSample *a, const LweSample *b) {
        //     for (size_t i = 0; i < 16; i++)
        //     {

        //         bootsXOR()
        //     }
            
        // }

        LweSample *minimum(vector<LweSample *> a, const int nb_bits, const TFheGateBootstrappingCloudKeySet *bk, int x, int y)
        {
            LweSample *tmps = new_gate_bootstrapping_ciphertext_array(2, bk->params);
            LweSample *res = new_gate_bootstrapping_ciphertext_array(16, bk->params);

            bootsCONSTANT(&tmps[0], 0, bk);

            for (int i = 0; i < nb_bits; i++)
                compare_bit(&tmps[0], &a[x][i], &a[y][i], &tmps[0], &tmps[1], bk);
            for (int i = 0; i < nb_bits; i++)
                bootsMUX(&res[i], &tmps[0], &one[i], &zero[i], bk);
            delete_gate_bootstrapping_ciphertext_array(2, tmps);
            return (res);
        }

        void getMinimum()
        {
            for (size_t i = 0; i < ciphertext1.size(); i++)
            {
                LweSample *tmp = zero;
                for (size_t j = 0; j < ciphertext1.size(); j++)
                {
                    cout << i << " / " << j << endl;
                    if (j != i)
                        tmp = addition(tmp, minimum(ciphertext1, 16, cloudKey, i, j));
                    else
                        tmp = addition(tmp, one);
                }
                ciphertext2[i] = tmp;
            }
            exportAnswers();
        }

        void exportAnswers()
        {
            FILE *cloud_data = fopen("answer.data", "wb");
            for (size_t j = 0; j < ciphertext2.size(); j++)
            {
                for (int i = 0; i < 16; i++)
                    export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext2[j][i], cloudKey->params);
            }
            fclose(cloud_data);
        }
    };
} // namespace std