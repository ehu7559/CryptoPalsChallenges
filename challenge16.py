#Challenge 16: CBC bitflipping attacks
from challenge10 import AES_CBC_128 as CBC
from os import urandom
from helpers import safe_string

#Generates the oracle for encrypted cookies, used to hide the key from the attacker function.
def chall16_encrypted_oracle(aes_key : bytes, aes_iv : bytes):
    oracle_pre = "comment1=cooking%20MCs;userdata=".encode("utf-8")
    oracle_suf = ";comment2=%%20like%%20a%20pound%%20of%%20bacon".encode("utf-8")
    return lambda x : CBC.encrypt((oracle_pre + bytes(x) + oracle_suf), aes_key, aes_iv)

def chall16_checker_oracle(aes_key: bytes, aes_iv: bytes): 
    return lambda x : check_win(CBC.decrypt(x, aes_key, aes_iv))

def check_win(plain_text: bytes) -> bool:
    #This inefficient checking is to accomodate the bytes type.
    print(safe_string(plain_text))
    target_substring = ";admin=true;".encode() 
    ptr = 0
    for c in plain_text:
        if c == target_substring[ptr]:
            ptr += 1
            if ptr == len(target_substring): return True
            continue
        ptr = 0 #Reset
    return False

#Oracle-generation function.
def generate_oracles() -> tuple:
    #Generate AES key
    challenge_key = urandom(16)
    challenge_iv= urandom(16)
    
    #Generate actual oracles
    oracle_a = chall16_encrypted_oracle(challenge_key, challenge_iv)
    oracle_b = chall16_checker_oracle(challenge_key, challenge_iv)

    #Remove key and iv variables. This is a symbolic gesture to show no other use of the key/iv.
    del challenge_key
    del challenge_iv

    #Return the two oracles
    return (oracle_a, oracle_b)

#Attack function
def attack_chall16(oracle) -> bytes:
    #Generate base
    payload = bytes(16) #I've opted to use a fixed null value rather than filtering chars.
    oracle_base = bytearray(oracle(payload))

    target_string = ";admin=true;"
    for i in range(len(target_string)):
        oracle_base[i + 16] = oracle_base[i + 16] ^ ord(target_string[i])
    
    return bytes(oracle_base)


#Challenge code
if __name__ == "__main__":

    #Get the oracles
    chall_a, chall_b = generate_oracles()

    #Run challenge and print result
    sliced_message = attack_chall16(chall_a)
    print("CORRECT" if chall_b(sliced_message) else "WRONG")
    print("--- CHALLENGE STATUS: COMPLETE ---")
