#Set 1, Challenge 1: Convert hex to base64
from base64 import b64decode

def hex_to_base64decode(hex_string : str) -> str:
    return b64decode(bytes.fromhex(hex_string))