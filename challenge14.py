# Challenge 14
from random import randint
from base64 import b64decode

if __name__ == "__main__":
    data = b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")

    #print(len(data))

    testkey = bytearray(16) #AES Key set to null for testing.
    chall_oracle = get_chall12_oracle(data)
    
    #print(len(chall_oracle(bytes())))    
    solution = attack_chall12(chall_oracle)
    
    print(solution.decode())