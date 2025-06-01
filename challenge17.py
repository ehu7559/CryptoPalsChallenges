#Challenge 17: CBC Padding Oracle Attack

#Imports
from base64 import b64decode
from challenge2 import xor_buf
from challenge7 import AES_primitives
from challenge10 import AES_CBC_128 as CBC
from random import choice
from os import urandom

#Padding Oracle (In a real attack this would send a request and judge by server response)
def get_padding_oracle(aes_key: bytes):
    return lambda ct, iv : padding_oracle(aes_key, ct, iv)

def attack_block(oracle, block: bytes) -> bytes:
    #Initialize brute-force procedure    
    zeroing_iv = bytearray(16)
    output = bytearray(16)
    desired_pad_len = 1
    for i in range(15, -1, -1):
        #print(f"Pad Length: {desired_pad_len}")
        #Re-adjust the previously determined IV
        for j in range(i + 1, 16): zeroing_iv[j] = output[j] ^ desired_pad_len
        
        found = False
        for j in range(256):
            #print(f"i={i}, j={j}     ", end="\r")
            zeroing_iv[i] = j
            if not (oracle(block, zeroing_iv)): continue
            
            #Making sure the first byte hits 0x01 rather than something else.
            if i == 15:
                zeroing_iv[14] = 1
                if not oracle(block, zeroing_iv): continue

            output[i] = zeroing_iv[i] ^ desired_pad_len
            found = True
            break
        
        if not found: raise Exception("FAILURE")

        #Increment desired pad length
        desired_pad_len += 1

    return output

def padding_oracle(aes_key, ciphertext, aes_iv):
    #Check for block convention
    if len(ciphertext) % 16: return False
    #Get _last_ block, updating IV and ciphertext accordingly
    while len(ciphertext)>16: aes_iv, ciphertext = ciphertext[:16], ciphertext[16:]
    plainblock = AES_primitives.decrypt_block_128(ciphertext,aes_key)
    plainblock = xor_buf(aes_iv, plainblock)
    print(plainblock.hex(), end="\r")
    return AES_primitives.validate_PKCS7_Padding(plainblock) 

#Main Attack Loop
def attack(oracle, ciphertext: bytes, init_vector: bytes) -> bytes:
    #Break it into blocks.
    print(ciphertext.hex())
    num_chunks = len(ciphertext) // 16
    ct_blocks = [ciphertext[i*16 : (i+1)*16] for i in range(num_chunks)]
    plaintext = bytes()
    iv_blocks = [init_vector] #The corresponding initialization vectors

    #load more initialization vectors
    iv_blocks.extend(ct_blocks)
    iv_blocks.pop() #Don't need last block (it's not used as an IV)

    #Process each attack individually
    #This is trivial to prove correct.
    for i in range(num_chunks): 
        print(f" Cracking Ciphertext Block {i}: {ct_blocks[i].hex()}")
        plaintext += xor_buf(attack_block(oracle, ct_blocks[i]), iv_blocks[i])
        print(plaintext.decode())

    #Join and return output
    return AES_primitives.trim_pkcs7_padding(plaintext)

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