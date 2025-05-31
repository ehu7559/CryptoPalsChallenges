#Set 1, Challenge 2: Fixed XOR
def xor_buf(a : bytes, b : bytes) -> bytes:
    assert(len(a)==len(b))
    a, b = bytes(a), bytes(b)
    return bytes([a[x] ^ b[x] for x in range(min(len(a), len(b)))])

def xor_hex(a : str, b : str) -> str:
    assert(len(a) == len(b))
    a, b = str(a), str(b)
    return xor_buf(bytes.fromhex(a), bytes.fromhex(b)).hex()
