#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>

int main() {
    //generate a keyset

    //**************//
    //STEP 1:GENERATE AND STORE PARAMS
    
    //generate params
    const int minimum_lambda = 110;
    TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(minimum_lambda);
    // export the parameter to file for later use
    FILE* params_file = fopen("params.key","wb");
    export_tfheGateBootstrappingParameterSet_toFile(params_file, params);
    fclose(params_file);

    //**************//
    //STEP 2: GENERATE AND STORE FHE KEYSET
    //generate a random key
    uint32_t seed[] = { 314, 1592, 657 };
    tfhe_random_generator_setSeed(seed,3);
    TFheGateBootstrappingSecretKeySet* key = new_random_gate_bootstrapping_secret_keyset(params);

    //export the secret key to file for later use
    FILE* secret_key = fopen("secret.key","wb");
    export_tfheGateBootstrappingSecretKeySet_toFile(secret_key, key);
    fclose(secret_key);

    //export the cloud key to a file (for the cloud)
    FILE* cloud_key = fopen("cloud.key","wb");
    export_tfheGateBootstrappingCloudKeySet_toFile(cloud_key, &key->cloud);
    fclose(cloud_key);
   

    //**************//
    //clean up all pointers
    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);

}
