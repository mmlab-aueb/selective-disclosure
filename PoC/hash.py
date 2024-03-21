import json 
import base64
import time
import hashlib
from jwcrypto import jwk, jws
from secrets import token_bytes

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
proof_object = []
key = jwk.JWK.generate(kty='EC', crv='P-256')
start_time = time.time()
for item in all_disclosures:
    salt = base64.b64encode(token_bytes(16)).decode()
    item.append(salt)
    disclosure_sha256 = hashlib.sha256()
    disclosure_sha256.update(json.dumps(item).encode('utf-8'))
    proof_object.append(base64.b64encode(disclosure_sha256.digest()).decode())

proof = jws.JWS(json.dumps(proof_object).encode('utf-8'))
proof.add_signature(key, None,{"alg": "ES256"})
object_signature= proof.serialize(compact=True)
end_time = time.time()

print("Signing completed in: \t %s" % (end_time - start_time))

for x in range(100):
    print("Revealing %s disclosures:" % (x+1))
    disclosures = []
    start_time = time.time()
    for y in range(x+1):
        disclosures.append(all_disclosures[y])
    disclosures_b64 = base64.b64encode(json.dumps(disclosures).encode()).decode()
    end_time = time.time()
    print("\t Proof size: %s:" % (len(object_signature)))

    #Verifier
    claimed_proof = jws.JWS()
    received_disclosures=[]
    start_time = time.time()
    claimed_proof.deserialize(object_signature)
    claimed_proof.verify(key) #step 1
    
    for y in range(x+1):
        disclosure_sha256 = hashlib.sha256()
        disclosure_sha256.update(json.dumps(all_disclosures[y]).encode('utf-8'))
        index = base64.b64encode(disclosure_sha256.digest()).decode() #step 2
        if index in proof_object: #step 3
            received_disclosures.append(all_disclosures[y])
    end_time = time.time()
    print("\t Verification time: \t %s" %  ((end_time - start_time)*1000)) #verifier
