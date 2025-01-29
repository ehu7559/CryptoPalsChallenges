#Cryptopals challenge 13
from challenge7 import AES_ECB_128

#Cookie parsing function:
def parse_cookie(text : str) -> dict:
    '''A naive and insecure parsing function as requested for the challenge.'''
    output = {}
    pairs = text.split(sep="&")
    for p in pairs:
        keyval = p.split(sep="=")
        if len(keyval) < 2: continue
        k, v = keyval[0], keyval[1]
        output[k] = v
    return output

#Cookie encoding function:
def profile_for(email : str) -> str:
    #Sanitize by just removing them all
    email = email.replace("&", "").replace("=", "")
    return f"email={email}&uid=10&role=user"

#Generate Oracles
def get_oracles():
    from random import randint
    aes_key = bytes([randint(0,255) for _ in range(16)])

    encryptor_oracle = lambda x : AES_ECB_128.encrypt(profile_for(str(x)).encode(), aes_key)
    validator_oracle = lambda x : parse_cookie(AES_ECB_128.decrypt(x, aes_key).decode())["role"]=="admin"

    return (encryptor_oracle, validator_oracle, aes_key) #Discard key when unpacking tuple if secrecy is desired.

#Attacker Function:
def forge_cookie(profileoracle):
    #Feed the profile oracle a bad email address to get the parts for cut and paste
    bademailaddr = "fake_usernadmin\v\v\v\v\v\v\v\v\v\v\vame"
    badprofile = bytes(profileoracle(bademailaddr))

    #Move the encrypted chunks around. We know this is going to be 4 chunks, but we only need the first 3.
    chunka, chunkb, chunkc = bytes(badprofile[0:16]),bytes(badprofile[16:32]),bytes(badprofile[32:48])

    #Return the forged cookie.
    return bytes(chunka + chunkc + chunkb)

#Challenge main code
if __name__ == "__main__":
    chall_profile_oracle, chall_validator_oracle, chall_key = get_oracles()
    cookie = forge_cookie(chall_profile_oracle)
    decrypted_cookie = AES_ECB_128.decrypt(cookie, chall_key).decode()
    print(f"Forged Cookie Decryption: {decrypted_cookie}")
    print(f"Forged Cookie Parsed: {parse_cookie(decrypted_cookie)}")
    print(f"Validation Passes?: {chall_validator_oracle(cookie)}")