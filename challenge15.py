def validate_PKCS7_Padding(buf : bytes) -> bool:
    #Check length is compliant.
    #Must be non-zero multiple of 16 as padding is at least one byte.
    if len(buf) % 16 or len(buf) == 0: return False

    #Get the pad length, check validity
    pad_implied_size = buf[-1]
    if pad_implied_size > 16: return False

    #Check the rest of the pad's implied length.
    for i in range(-1, -1-pad_implied_size, -1):
        if buf[i] != pad_implied_size: return False
    
    #No other fails, passes verification.
    return True

def trim_pkcs7_padding(buf : bytes) -> bool:
    assert(validate_PKCS7_Padding(buf))
    pad_implied_size = buf[-1]
    return bytes(buf[:0-pad_implied_size])