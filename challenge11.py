from challenge7 import AES_ECB_128 as ECB
from challenge10 import AES_CBC_128 as CBC
from challenge8 import probablyECB
from random import randint, choice

encrypt_with_ecb = lambda buf : ECB.encrypt(buf, bytes([randint(0,255) for _ in range(16)]))
encrypt_with_cbc = lambda buf : CBC.encrypt(buf, aes_key=bytes([randint(0,255) for _ in range(16)]), iv=bytes([randint(0,255) for _ in range(16)]))

blinded_crypt = lambda x : encrypt_with_ecb if x else encrypt_with_cbc

def rand_crypt(buf : bytes) -> bytes:
    #Generate random buffer for beginning
    prefix = bytes([randint(0,255) for _ in range(randint(5,10))])
    suffix = bytes([randint(0,255) for _ in range(randint(5,10))])

    mode = choice([True, False])
    encryptor = blinded_crypt(mode)
    return (mode, encryptor(bytes(prefix + buf + suffix)))

if __name__ == "__main__":
    print("RUNNING CHALLENGES")
    failed = False
    for i in range(100):
        ans, chall = rand_crypt(bytes([0] * 256))
        if probablyECB(chall) != ans:
            failed = True
            break
    print("FAILED" if failed else "PASSED")