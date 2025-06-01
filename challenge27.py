#Challenge 27: Recover the key from CBC with IV=Key

#Imports
from os import urandom
from challenge2 import xor_buf
from challenge7 import AES_primitives
from challenge10 import AES_CBC_128 as CBC

#Validation function
def is_valid_ciphertext(data, key, iv):
    plain_data = decrypt_AES_CBC_no_trim(data, key, iv)
    return not any(map(lambda x : x > 127, plain_data))

def decrypt_AES_CBC_no_trim(data, key, iv):
    if len(data) % 16 or len(key) != 16 or len(iv) !=16:
        raise Exception("Wrong size of buffers provided")
    output = bytes()
    while data:
        block = data[:16]
        output += xor_buf(iv, AES_primitives.decrypt_block_128(block, key))
        iv, data = data[:16], data[16:]
    return output

def get_server_oracle(key, iv):
    return lambda x : bytes() if is_valid_ciphertext(x, key, iv) else decrypt_AES_CBC_no_trim(x, key, iv) 

#Attack Function
def attack(intercepted_message, decryption_server):
    if len(intercepted_message) < 16:
        #Not even a whole ciphertext block. Basically impossible.
        print("ERROR: Message length is insufficient to conduct attack")
        return
    payload = bytes(intercepted_message[:16]) + bytes(16) + bytes(intercepted_message[:16])
    newplain = decryption_server(payload)
    if len(newplain) == 0:
        print("ERROR: Message transformation did not trigger server failure")
    recovered_key = bytes([newplain[i] ^ newplain[i+32] for i in range(16)])
    return recovered_key 

#Challenge Code
if __name__ == "__main__":
    #Generate key
    print("GENERATING KEY/IV VALUES...")
    chall_key = urandom(16)
    chall_iv = chall_key

    #Server generation
    print("SETTING UP CHALLENGES...")
    chall_server = get_server_oracle(chall_key, chall_iv)
    #Generate sender message
    
    plain_message = "This message being displayed indicates challenge completion.".encode("ascii")
    encrypted_message = CBC.encrypt(plain_message, chall_key, chall_iv)

    #Perform attack
    print("PERFORMING ATTACK...")
    cracked_key = attack(encrypted_message, chall_server)
    print(f"CHALLENGE KEY: \t{chall_key.hex()}")
    print(f"CRACKED KEY: \t{cracked_key.hex()}")
    cracked_text = CBC.decrypt(encrypted_message, cracked_key, cracked_key)
    print("RECOVERED MESSAGE: " + cracked_text.decode("ascii"))

    print(f"--- CHALLENGE STATUS: {'COMPLETE' if chall_key.hex() == cracked_key.hex() else 'ERROR'} ---")