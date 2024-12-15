from challenge3 import TextScorer, SingleByteXOR

if __name__ == "__main__":
    hexes = []
    with open("challdata/4.txt", "r") as f: hexes = f.readlines()
    max_score = 0
    max_text = None
    for h in hexes:
        buf = bytes.fromhex(h)
        x = SingleByteXOR.top_single_byte_xor(buf)
        text = SingleByteXOR.apply(buf, x)
        score = TextScorer.score_buf(text)
        if score > max_score:
            max_score = score
            max_text = text
    print(f"SOLUTION: '{max_text.decode()}'")