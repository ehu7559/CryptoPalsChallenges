def probablyECB(buf : bytes) -> bool:
    if len(buf) % 16: return False #Ciphertext is not in chunks or is empty.
    numchunks = len(buf)//16
    chunks = [bytes(buf[16*i : (16 * (i + 1))]) for i in range(numchunks)]
    return len(set(chunks)) < numchunks

if __name__ == "__main__":
    with open("challdata/8.txt", "r") as f:
        for l in f.readlines():
            buf = bytes.fromhex(l.strip())
            if probablyECB(buf): l