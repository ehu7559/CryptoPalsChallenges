def repeating_key_XOR(buf : bytes, keybuf: bytes) -> bytes:
    return bytes([buf[i] ^ keybuf[i%len(keybuf)] for i in range(len(buf))])
