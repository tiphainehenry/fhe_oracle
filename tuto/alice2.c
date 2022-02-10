#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>

int main() {
  
    // LOAD PARAMS AND SECRET KEY
    FILE* params_file = fopen("params.key", "rb");
    TFheGateBootstrappingParameterSet* params= new_tfheGateBootstrappingParameterSet_fromFile(params_file);
    fclose(params_file);

    FILE* secret_key = fopen("secret.key","rb");
    TFheGateBootstrappingSecretKeySet* key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
    fclose(secret_key);


    //generate encrypt the 16 bits of 62
    int16_t plaintext1 = 62;
    LweSample* ciphertext1 = new_gate_bootstrapping_ciphertext_array(16, params);
    for (int i=0; i<16; i++) {
        bootsSymEncrypt(&ciphertext1[i], (plaintext1>>i)&1, key);
    }


    printf("Hi there! Today, I will ask the cloud to evaluate the minimum between %d and the other offer\n",plaintext1);
    
    //export the 2x16 ciphertexts to a file (for the cloud)
    
    FILE* cloud_data = fopen("2.cloud.data","wb");
    for (int i=0; i<16; i++) 
        export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext1[i], params);
    fclose(cloud_data);


    //clean up all pointers
    delete_gate_bootstrapping_ciphertext_array(16, ciphertext1);    //...

    //clean up all pointers
    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);

}
