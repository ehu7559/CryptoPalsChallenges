from base64 import b64decode
from challenge18 import AES_CTR as CTR
from challenge6 import bitwiseVigenereCrack #Imported my vigenere cracking function
from challenge5 import repeating_key_XOR
from helpers import safe_string

if __name__ == "__main__":
    with open("challdata/20.txt", "r") as f:
        #pull ciphertexts
        lines = f.readlines()
        ciphertexts = [bytes(b64decode(l)) for l in lines]
        
        #Truncate to min length
        lowlen = min([len(c) for c in ciphertexts])
        truncated_ciphertexts = [bytes(c[:lowlen]) for c in ciphertexts]

        longtext = bytes()
        for t in truncated_ciphertexts: longtext += t

        #Use challenge 6's function. I've modified it to take an optional known key length.
        key = bitwiseVigenereCrack(longtext, keysize=lowlen)

        #Decrypt
        for c in ciphertexts:
            print(safe_string(repeating_key_XOR(c, key)))
