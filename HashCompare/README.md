HashCompare
===========
this repo contain the Hashcompare prototype, the RestAPI using hashcompare and the SmartContract used to link the API to the blockchain.

Hashcompare
===========
Prototype taking n parameters encrypt them and then return a vector with the values ordered from the highest to the lowest.

Install
-------
Requirements:

    * [TFHE] (https://tfhe.github.io/tfhe/installation.html).
    * [CRYPTO++] (https://www.cryptopp.com/wiki/Linux#Distribution_Package)
Compiling
---------

    $ cd Hashcompare
    $ make
    $ #or
    $ ./comp.sh
    $ # ./comp.sh clean can be used to remove temporary files.

Usage
---
See /HashCompare/comp.sh
