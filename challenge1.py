from base64 import b64decode

def hex_to_base64decode(hex_string : str) -> str:
    return b64decode(bytes.fromhex(hex_string))