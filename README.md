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

RestHash
========
Rest API using Hashcompare

Install
-------
Requirements:

* [TFHE](http://tfhe.github.io/tfhe/installation.html)

* [CRYPTOpp](https://www.cryptopp.com/wiki/Linux#Distribution_Package -- an issue may occur with ++ instead of pp)

* [IPFS](https://github.com/vasild/cpp-ipfs-http-client)

* [CPPRestSDK](https://github.com/microsoft/cpprestsdk/wiki/How-to-build-for-Linux)

* [Nlohmann]

* [boost] (https://www.boost.org/doc/libs/1_61_0/more/getting_started/unix-variants.html)

Compiling
---------
    $./comp.sh

Smart Contract
====
[Work in progress]
---

* Oracle.sol
    - oracle using provable to access to a public API and stocking the value
* TenderManager.sol
    - Smart contract managing Tenders and offers. each struct contain the IPFS link to their respectives data.

Usage
---

Compile and test via [Remix](https://remix.ethereum.org/#version=soljson-v0.5.16+commit.9c3226ce.js&optimize=false&evmVersion=null&gist=8a28f5ee239b7815b935d883f1239904&runs=200).
