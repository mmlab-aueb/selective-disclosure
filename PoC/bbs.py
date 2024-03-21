import json 
import base64
import time
import hashlib
from jwcrypto import jwk, jws
from secrets import token_bytes
from ursa_bbs_signatures import ProofMessage, ProofMessageType, CreateProofRequest, create_proof
from ursa_bbs_signatures import BlsKeyPair, sign, SignRequest, VerifyProofRequest, verify_proof

def _get_disclosures(json_object, disclosures, prefix):
    if isinstance(json_object, dict):
        for key, value in json_object.items():
            claim =  prefix + "/" + key
            disclosures.append([claim,value])
            if isinstance(value, dict) or isinstance(value, list):
                _get_disclosures(value, disclosures, claim)
    elif isinstance(json_object, list):
        for key in range(len(json_object)):
            claim =  prefix + "/" + str(key)
            value = json_object[key]
            disclosures.append([claim,value])
            if isinstance(value, dict) or isinstance(value, list):
                _get_disclosures(value, disclosures, claim)
    return disclosures
    

def disclosures(json_object):
    claims = _get_disclosures(json_object, [], "")
    return claims

def _set_claim(json_object, keys, value):
    key = keys[0]
    if key not in json_object:
        json_object[key]={}
    if (len(keys)==1):
        json_object[key]=value
    else:
        keys.pop(0)
        _set_claim(json_object[key], keys, value) 

def json_object(disclosures):
    output = {}
    for disclosure in disclosures:
        claim = disclosure[0]
        value = disclosure[1]
        keys = claim.split("/")
        keys.pop(0) # remove $
        _set_claim(output,keys,value)
    return output

f = open('artifact.json')
json_object = json.load(f)
all_disclosures = disclosures(json_object)
all_disclosures_b64 = base64.b64encode(json.dumps(all_disclosures).encode()).decode()
proof_object = []
public_bls_key = b"\x86M\xc0cUPQ\xdb\xdblE\x87E\x832p8\xf5\xb9\xbeM\x05\xf1G\x9emHe\x99\xf0T\xbfn\x85" \
                              b"\x18\xdb\x86'W\x1c\xe3" \
                              b"\x8aG\x97S\x01\xda\xfe\x0e\x15)\x144I\xf9\xd0:\xcc\xdb\xc5\xc26\x10\xf9@\xaa\x18\xf5," \
                              b"6Es\xfd\xc7\xf1tcZ\x98\xfe\xd6\xcct\xbfk\xfb\x9f\xf1\xad)\x15\x88w\x80\xdd\xea "
secret_bls_key = b'\x06\xe7w\xf4\x90\x0e\xacK\xb7\x94l\x00/\xaaFD\x1c\xff\x9c\xad\xdcq\xed\xb6#%\x7fu' \
                              b'\xc7\x8c\xfe\x9c '
start_time = time.time()
for item in all_disclosures:
    proof_object.append(json.dumps(item))
key_pair = BlsKeyPair(public_bls_key, secret_bls_key)
sign_request = SignRequest(key_pair, proof_object)
signature = sign(sign_request)
end_time = time.time()
print("sign \t %s" % (end_time - start_time))

for x in range(100):
    print("Revealing %s disclosures:" % (x+1))
    disclosures = []
    public_key = key_pair.get_bbs_key(message_count=100)
    start_time = time.time()
    proof_messages = []
    for y in range(x+1):
        disclosures.append(json.dumps(all_disclosures[y]))
        proof_messages.append(ProofMessage(json.dumps(all_disclosures[y]), ProofMessageType(1)))
    for y in range(x+1,100):
        proof_messages.append(ProofMessage(json.dumps(all_disclosures[y]), ProofMessageType(2)))
    
    proof_request = CreateProofRequest(public_key=public_key,
                                    messages=proof_messages, 
                                    signature=signature, 
                                    nonce=b'PROOF_NONCE')
    proof = create_proof(proof_request) 
    disclosures_b64 = base64.b64encode(json.dumps(disclosures).encode()).decode()
    proof_64 = base64.b64encode(proof).decode()
    end_time = time.time()
    print("\t Proof size: %s:" % (len(proof_64)))

    #Verifier
    start_time = time.time()
    verify_result = verify_proof(
        VerifyProofRequest(
            public_key=public_key,
            proof=proof,
            messages=disclosures,
            nonce=b'PROOF_NONCE'
        )
    )
    end_time = time.time()
    print("\t Verification time: \t %s" %  ((end_time - start_time)*1000)) #verifier


