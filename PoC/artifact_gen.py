import random
import string
import json

json_object = dict()
for x in range(100):
    key = ''.join(random.choices(string.ascii_lowercase, k=5))
    value = ''.join(random.choices(string.ascii_lowercase, k=5))
    json_object[key] = value

print(json.dumps(json_object, indent=4))
