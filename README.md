# Data integrity protection for data spaces
This repository includes a proof-of-concept of the solution presented in the paper

> N. Fotiou, Y. Thomas, and G. Xylomenos, "Data integrity protection for data spaces", in Eurosec 2024

The proposed solution allows JSON objects to be signed is way that any 3rd party can
selectively reveal portions of the JSON object, providing at the same time an integrity
proof.

## Solution Overview
Signing a JSON object using our solution is a two steps process. The first step
is ``object decomposition intro a list of disclosures'' and the second step is
``disclosures signing''. Disclosures signing can be implemented either by signing 
salted hashes of the disclosures or by using BBS+ signatures.

### Object decomposition
The first step of our solution is object decomposition intro a list of disclosures. 
A disclosure represents a member of the JSON object. For composite members, i.e., members
whose value is a JSON object, a disclosure is constructed for all sub-members, following 
a depth-first approach. A disclosure is composed of two parts: the disclosure name 
whose value is the [JSON pointer](https://datatracker.ietf.org/doc/html/rfc6901) to 
the corresponding member, i.e., a string representing the ``path'' to that member in the
JSON-LD object, and the disclosure value which contains the corresponding member value. 

As an example consider the following JSON object

```JSON
{
    "id": "did:self:iQ9PsBKOH1nLT9Fyhs",
    "type": "car",
    "color": "black",
    "speed": 30,
    "brand": {
        "company": "bmw",
        "model": "i5"
    }
}
```
This object is decomposed in the following disclosures

| Name | Value |
| --- | --- |
| /id | did:self:iQ9PsBKOH1nLT9Fyhs |
| /type | car |
| /color | black |
| /speed | 30 |
| /brand | {'company': 'bmw', 'model': 'i5'} |
| /brand/company | bmw |
| /brand/model | i5 |

### Hash-based signatures
Hash-based signing of disclosures is implemented using the following steps:

* Initially, the signer calculates the disclosures of a JSON object and transforms 
each disclosure into a single message by concatenating the disclosure name with 
the disclosure value, plus a random salt value, separating them using the space character. 
* For each message the signer calculates its hash.
* The signer concatenates the base64 encoding of all hashes into a list 
and digitally signs it using JSON Web Signatures (JWS): the JWS object is used as the signature of the disclosures. 

Any third party can now reveal a portion of the disclosures. A verifier can verify 
their integrity and construct a composite object, as follows:

* The verifier validates the signature of the disclosures using the public key of signer.
* For the available disclosures, the verifier reconstructs the messages that the signer 
created in the first step of the signing algorithm (including the salt values).
* For each message, the verifier calculates its hash and verifies that it is included in the signature of the disclosures.
* Finally, verifier creates a composite JSON object using the name and value of each provided disclosure. 

### BBS+ signatures
The list of disclosure can also be signed using [BBS+](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-04.html)
signatures. In this case signing is implemented as follows:

* Initially, a signer calculates the disclosures of a JSON object and transforms 
each disclosure into a single message by concatenating the disclosure name and value, 
separating them using the space character. 
* Then, it generates a BBS+ signature providing as input its private key and the list of disclosures. 


Any third party can now reveal a portion of the disclosures. A verifier can verify 
their integrity and construct a composite object, as follows:

* For the available disclosures, the verifier reconstructs the messages that the 
singer calculated in the first step of the signing algorithm.
* The verifier verifies that the provided ZKP is a valid proof for the calculated messages.
* Finally, the verifier extracts the name and value of each disclosure and creates a composite JSON object. 

## PoC execution
The PoC folder includes scripts for benchmarking the signing algorithms. 
First execute these commands to install the required python3 packages:

```bash
python3 -m pip install secrets
python3 -m pip install jwcrypto
python3 -m pip install jwcryptoursa-bbs-signatures
```

Then, run the `artifact_gen.py` script which generates an moke json object that 
includes 100 attributes.

```bash
python3 artifact_gen.py
```

To run the benchmark script for the hash-based approach execute the `hash.py' script

```bash
python3 hash.py
```
