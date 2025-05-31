#Challenge 17: CBC Padding Oracle Attack

#Imports
from base64 import b64decode
from challenge2 import xor_buf
from challenge7 import AES_primitives
from challenge15 import trim_pkcs7_padding, validate_PKCS7_Padding #For trimming
from challenge10 import AES_CBC_128 as CBC
from random import choice
from os import urandom

#Padding Oracle (In a real attack this would send a request and judge by server response)
def get_padding_oracle(aes_key: bytes):
    return lambda ct, iv : validate_PKCS7_Padding(naive_decrypt_CBC(ct, aes_key, iv))

def attack_block(oracle, block: bytes) -> bytes:
    #Initialize brute-force procedure    
    zeroing_iv = bytearray(16)
    output = bytearray(16)
    desired_pad_len = 1
    for i in range(15, -1, -1):
        #Re-adjust the previously determined IV
        for j in range(i + 1, 16):
            zeroing_iv[j] = output[j] ^ desired_pad_len
        found = False
        for _ in range(256): #Brute force that byte of the pad.
            if oracle(block, zeroing_iv):

                #Check for 01 bytes only.
                if i == 15:
                    #increment preceding byte and check
                    zeroing_iv[14] = (zeroing_iv[14] + 1) % 256
                    if not(oracle(block, zeroing_iv)): 
                        zeroing_iv[14] = (zeroing_iv[14] - 1) % 256
                        continue #If this happens, we accidentally hit a longer pad.
                    '''
                    NOTE:
                    Okay, I _could_ take the chance to roll back the search and cut the search space by a lot
                    but this is an edge case and it's simpler to just keep looking linearly.
                    '''
                #Add to output and break successfully.
                output[i] = zeroing_iv[i] ^ desired_pad_len
                found = True
                break
            zeroing_iv[i] = (zeroing_iv[i] + 1) % 256 #Increment byte.
        if not found: raise Exception("Attack Error: Could not find valid pad")
        desired_pad_len += 1
    return output

def naive_decrypt_CBC(data : bytes, aes_key : bytes, aes_iv : bytes):
    output = bytes()
    round_keys = AES_primitives.get_round_keys(aes_key)
    while len(data) > 0:
        #Decrypt
        plain_block = AES_primitives.ARK(data[:16], round_keys[10])
        for i in range(9,0,-1): plain_block = AES_primitives.decrypt_round(plain_block, round_keys[i]) 
        plain_block = AES_primitives.decrypt_final_round(plain_block, round_keys[0])
        
        #XOR
        plain_block = bytes([aes_iv[i] ^ plain_block[i] for i in range(16)])
        
        #Consume
        aes_iv, data = data[:16], data[16:]
        output += (plain_block)
    return bytes(output)


#Main Attack Loop
def attack(oracle, ciphertext: bytes, init_vector: bytes) -> bytes:
    #Break it into blocks.
    num_chunks = len(ciphertext) // 16
    ct_blocks = [ciphertext[i*16 : (i+1)*16] for i in range(num_chunks)]
    plaintext = bytes()
    iv_blocks = [init_vector] #The corresponding initialization vectors

    #load more initialization vectors
    iv_blocks.extend(ct_blocks)
    iv_blocks.pop() #Don't need last block (it's not used as an IV)

    #Process each attack individually
    #This is trivial to prove correct.
    for i in range(num_chunks): plaintext += xor_buf(attack_block(oracle, ct_blocks[i]), iv_blocks[i])

    #Join and return output
    return trim_pkcs7_padding(plaintext)

def choose_text() -> bytes:
    with open("challdata/17.txt", "r") as f:
        return bytes(b64decode(choice(f.readlines()).strip()))

def get_challenge() -> tuple:
    #Generate key
    chall_key = urandom(16)
    chall_iv = urandom(16)
    chall_txt = choose_text()

    print("TARGET: " + chall_txt.decode('ascii'))
    #Encrypt text
    ciphertext = CBC.encrypt(chall_txt, chall_key, chall_iv)

    #Create Oracle
    chall_oracle = get_padding_oracle(chall_key)

    #Symbolic deletion gesture
    del chall_key
    del chall_txt

    #Return ciphertext, iv, and oracle
    return (ciphertext, chall_iv, chall_oracle)

#CHALLENGE CODE:
if __name__ == "__main__":
    chall_ct, chall_iv, chall_o = get_challenge()
    plain_text = attack(chall_o, chall_ct, chall_iv)
    print("RESULT: " + plain_text.decode("utf-8"))
    print("--- CHALLENGE STATUS: COMPLETE ---")