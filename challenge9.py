#Generalized form as requested in challenge prompt.
def pad_pkcs7(buf, blocksize):
    padnum = ((0 - buf) % blocksize) % 256 #Fits within byte.
    return buf + bytes([padnum] * padnum)

def trim_pkcs7(buf, blocksize):
    lastblockstart = 