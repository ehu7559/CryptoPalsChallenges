#Challenge 25: Break "random access read/write" AES CTR

#Imports
from random import randint
from challenge18 import AES_CTR as CTR
from challenge7 import AES_ECB_128 as ECB
from os import urandom

#Ciphertext Generator
def generate_challenge(chall_text : bytes):
    nonce = randint(0, 2**64 - 1)
    key = urandom(16)
    challenge_text = CTR.encrypt(ECB.decrypt(chall_text, bytes("YELLOW SUBMARINE","ascii")), key, nonce)
    return (challenge_text, (lambda x: CTR.encrypt(x, key, nonce)))

def edit_plain(base, edit, offset):
    return bytes([(edit[i - offset] if i in range(offset, offset + len(edit)) else base[i])for i in range(len(base))])

def generate_oracle(crypt):
    return (lambda a, b, c : crypt(edit_plain(crypt(a), b, c)))

#Challenge Attack Function
def attack(ciphertext, oracle):
    return oracle(ciphertext, ciphertext, 0)

#Challenge Code
if __name__ == "__main__":
    with open("challdata/7.txt", "r") as f:
        from base64 import b64decode
        ciphertext = b64decode("".join([x.strip() for x in f.readlines()]))
        #Generate Challenge
        chall_ct, chall_crypt = generate_challenge(ciphertext)

        #Generate oracle
        chall_oracle = generate_oracle(chall_crypt)

        #Attack
        chall_flag = attack(chall_ct, chall_oracle).decode("ascii")
        print(chall_flag)
        #Challenge status
        print("--- CHALLENGE STATUS: COMPLETE ---")