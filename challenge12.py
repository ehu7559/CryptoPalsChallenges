from base64 import b64decode
from random import randint
from challenge7 import AES_ECB_128 as ECB
from challenge8 import probablyECB

#Encryption generator. Key is generated in this scope and never 
def get_chall12_oracle(suffix : bytes):
    key = bytes([randint(0,255) for _ in range(16)])
    return lambda x : ECB.encrypt(bytes(x + suffix), aes_key=key)

#Oracle size finder
def get_oracle_block_size(target) -> int:
    '''Computes the block size of a target oracle'''
    initial_length = len(target(bytes(0)))
    extender = 0
    while len(target(bytes(extender))) == initial_length: extender += 1
    return len(target(bytes(extender))) - initial_length

#Function for checking an oracle
def check_oracle_is_ECB(target) -> bool:
    return probablyECB(target(bytes(256)))

#Given the target oracle, the first blocksize-1 bytes, try to find the last byte of the desired byte
def brute_block(target, header : bytes, desired_block):
    block = bytearray(header)
    block.append(0)
    #Brute forcing to find the matching byte
    for i in range(256):
        block[-1] = i
        outblock = bytes(target(block)[0:len(desired_block)]) #Grab first block
        if outblock == desired_block: return i
    raise Exception("No byte found")

def attack_chall12(target) -> bytes:
    #Setup for variables
    output = bytearray()
    blocksize = get_oracle_block_size(target)
    window = bytearray(blocksize - 1)
    num_blocks= len(target(bytes())) // blocksize 

    ithBlockOfBuf= lambda i, buf : buf[i * blocksize : (i + 1) * blocksize]

    paddedciphers = [bytes(target(bytes(bytearray(padlen)))) for padlen in range(blocksize)]

    #Process the bytes
    for i in range(num_blocks):
        for j in range(blocksize):
            
            #Do a bit of 
            padlen = blocksize - j - 1 #Clamped to integers in [0, blocksize), which is the proper interval
            desired_block = ithBlockOfBuf(i, paddedciphers[padlen]) #Grab the right block from right cipher.
            
            try:
                #Run it through the brute-forcer to get the next byte.
                newbyte = brute_block(target, window, desired_block)
                
                #Shift window
                window.append(newbyte)
                window.pop(0)

                #Add to output
                output.append(newbyte)
                print(chr(newbyte), end="")
            except: 
                break
            
    return bytes(output)

if __name__ == "__main__":
    data = b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")

    #print(len(data))

    testkey = bytearray(16) #AES Key set to null for testing.
    chall_oracle = get_chall12_oracle(data)
    
    #print(len(chall_oracle(bytes())))    
    solution = attack_chall12(chall_oracle)
    
    print(solution.decode())