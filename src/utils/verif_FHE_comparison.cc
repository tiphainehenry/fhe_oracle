#include <tfhe/tfhe.h>
#include <iostream>
#include <tfhe/tfhe_io.h>
#include <stdio.h>
#include <time.h>
#include <algorithm>
namespace std
{
    class Verif
    {
    private:
        TFheGateBootstrappingSecretKeySet *key;
        const TFheGateBootstrappingParameterSet *params;
        vector<LweSample *> answers;
        LweSample *test;
        vector<int> intAnswers;
        int offerCount;
        /* data */
    public:
        Verif(int offers)
        {
            string FHE_sk = get_filename("FHE_sk");
            FILE *secret_key = fopen(FHE_sk.c_str(), "rb");
            key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
            fclose(secret_key);
            params = key->params;
            test = new_gate_bootstrapping_ciphertext_array(16, key->params);
            offerCount = offers;
            for (size_t i = 0; i < offers; i++)
            {
                answers.push_back(new_gate_bootstrapping_ciphertext_array(16, key->params));
            }
        }
        ~Verif()
        {
        }

        string decrypt(string filename, int id)
        {

            FILE *answer_data = fopen(filename.c_str(), "rb");
            print_debug("filename = " + filename);
            for (size_t j = 0; j < offerCount; j++)
            {

                for (int i = 0; i < 16; i++)
                {

                    import_gate_bootstrapping_ciphertext_fromFile(answer_data, &test[i], params);
                }

                int16_t int_answer = 0;
                for (int i = 0; i < 16; i++)
                {
                    int ai = bootsSymDecrypt(&test[i], key) > 0;
                    int_answer |= (ai << i);
                }
                printf("And the result is: %d\n", int_answer);
                intAnswers.push_back(int_answer);
            }

            fclose(answer_data);

            switch (id)
            {

            // argmax
            case 1:
            {
                std::cout << " Maxed clear Vector" << std::endl;
                for (size_t i = 0; i < intAnswers.size(); i++)
                {
                    cout << " | " << intAnswers[i];
                }
                cout << " |" << endl;
                printf("Verification complete\n");

                std::vector<int>::iterator max = max_element(intAnswers.begin(), intAnswers.end());
                int argmaxVal = std::distance(intAnswers.begin(), max); // absolute index of max
                return to_string(argmaxVal);
            }
            break;

            // addition
            case 2:
                printf("Verification addition complete\n");
                return to_string(0);
                break;

            // substraction
            case 3:
                printf("Verification substraction complete\n");
                return to_string(0);
                break;

            default:
                return to_string(0);
                break;
            }
            return to_string(0);
        }
    };
}