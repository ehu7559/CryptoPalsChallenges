# Scoring values

#I've created a class here for future challenge importing
class TextScorer:
    CHAR_SCORES = {'e': 120, 't': 90, 'a': 80, 'i': 80, 'n': 80, 'o': 80, 's': 80, 'h': 64, 'r': 62, 'd': 44, 'l': 40, 'u': 34, 'c': 30, 'm': 30, 'f': 25, 'w': 20, 'y': 20, 'g': 17, 'p': 17, 'b': 16, 'v': 12, 'k': 8, 'q': 5, 'j': 4, 'x': 4, 'z': 2}
    alphabet = list(CHAR_SCORES.keys())
    for x in alphabet: CHAR_SCORES[x.capitalize()] = CHAR_SCORES[x] // 10 #Increased this factor until it selected the text I wanted.
    ignorable_chars = "1234567890!@#$%^&*(),.<>/?;:'\"[]\{\}\\|\n\t`~ "
    for x in ignorable_chars: CHAR_SCORES[x] = 1

    #This should be slightly faster for longer inputs as it removes hashing from the dict operations.
    BYTE_SCORES = [0] * 256
    for x in list(CHAR_SCORES.keys()): BYTE_SCORES[ord(x)] = CHAR_SCORES[x]

    def score_buf(buf : bytes, strict=True) -> int:
        buf = bytes(buf)
        output = 0
        for x in buf:
            if x > 128: return 0
            if strict and TextScorer.BYTE_SCORES[x]==None: return 0
            output += TextScorer.BYTE_SCORES[x]
        return output

    def score_text(text : str, strict=True) -> int:
        assert(type(text) is str)
        output = 0
        for c in text:
            val = TextScorer.CHAR_SCORES.get(c, 0) #Get with default value of 0 for none.
            if strict and val == 0: return 0
            output += val
        return output

class SingleByteXOR:
    def apply(buf : bytes, keybyte : int):
        return bytes([x ^ keybyte for x in buf])

    def brute_single_byte_xor(buf: bytes, strict=True):
        assert(type(buf) is bytes)
        return [TextScorer.score_buf(SingleByteXOR.apply(buf, x), strict=strict) for x in range(256)]

    def top_single_byte_xor(buf: bytes, strict=True):
        brute_scores = SingleByteXOR.brute_single_byte_xor(buf, strict)
        return max(list(range(256)), key=(lambda x : brute_scores[x]))

#Main Method
if __name__ == "__main__":
    texthex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    textbuf = bytes.fromhex(texthex)
    keybyte = SingleByteXOR.top_single_byte_xor(textbuf)
    print(SingleByteXOR.apply(textbuf, keybyte).decode())