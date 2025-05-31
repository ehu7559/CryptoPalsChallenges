#Makes a string safe(r) to print.
def safe_string(buf : bytes, safe_char = "*") -> str:
    return bytes([x if x < 128 else ord(safe_char) for x in buf]).decode()

#Joke function because funny
def xkcd_rand():
    return 4