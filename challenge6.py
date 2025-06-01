from base64 import b64decode
from challenge3 import SingleByteXOR
from challenge5 import repeating_key_XOR


#HAMMING DISTANCE FUNCTIONS
def hamming_distance(a : bytes, b : bytes) -> int:
    min_len = min(len(a), len(b))
    lendiff = abs(len(a) - len(b))
    output = lendiff * 8 #Any difference in length is automatically 8 bits of difference.

    #Calculate the hamming distance in the shared length
    for i in range(min_len): output += hamming_distance_byte(a[i], b[i])
    return output

def hamming_distance_byte(a : int, b : int):
    output = 0
    for _ in range(8):
        output += (a % 2) ^ (b % 2)
        a, b = a >> 1, b >> 1
    return output

#KASISKI ANALYSIS FUNCTIONS
def kasiski_wrap_score(buf : bytes, offset : int) -> int:
    '''Returns the hamming distance for a buffer and itself when wrapped by a given offset'''
    n = len(buf)
    return sum([hamming_distance_byte(buf[i], buf[(i + offset) % n]) for i in range(len(buf))])

def kasiski_wrap(buf : bytes, cap = 0) -> int:
    '''Returns the lowest Hamming distance offset for a buffer using the Kasiski wrap method'''
    if cap == 0: cap = len(buf)//2
    best_offset, best_score = 0, len(buf) * 8 
    for i in range(1, cap):
        kscore = kasiski_wrap_score(buf, i)
        if kscore < best_score: best_offset, best_score = i, kscore
    return best_offset

#DATA SPLITTING FUNCTION
def deal_data(buf : bytes, streams : int) -> list[bytes]:
    assert(streams > 0) # Need to have positive number of streams
    output = [bytes()] * streams
    for i in range(len(buf)): output[i%streams]+=bytes([buf[i]])
    #Cast as bytes and return list
    return [bytes(x) for x in output]

#Attack function (This is loosely based on what I remember of the Vigenere cipher attack I implemented in college)
def bitwiseVigenereCrack(buf: bytes, cap = 0, keysize = None) -> bytes:
    keylen = keysize if keysize else kasiski_wrap(buf, cap)
    keybuf = bytearray(keylen)
    streams = deal_data(buf, keylen)
    #print([hash(x) for x in streams])
    for i in range(keylen): keybuf[i] = SingleByteXOR.top_single_byte_xor(streams[i], strict=False)
    return bytes(keybuf)

if __name__ == "__main__":
    #Pull data
    encodedinput = ""
    with open("challdata/6.txt", "r") as f:
        for x in f.readlines(): encodedinput += x.strip()
    data = b64decode(encodedinput)

    #Get Key:
    key = bitwiseVigenereCrack(data, cap=100)
    keylen = len(key)
    text = repeating_key_XOR(data, key)
    print(f"Key Length: {keylen}")
    print(f"Key: {key.decode()}")
    print(f"Text: \n{text.decode()}")