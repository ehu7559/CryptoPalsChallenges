#AES-ECB Implementation
'''
--- WARNING ---
NOT INTENDED FOR CRYPTOGRAPHIC USE.
USE A MORE SECURE IMPLEMENTATION.
THIS IMPLEMENTATION IS FOR EDUCATIONAL PURPOSES ONLY.
---------------
This was done by hand for educational reasons. This is by no means an efficient
implementation (although efforts have been made to make this as streamlined as
possible), but it is a very understandable one. One can improve this by first
changing to a compiled language like C and then modified to take advantage of
any hardware shortcuts that might be available.
'''

#Constants and pre-computed lookup tables
NUM_ROUNDS=10
SB_TABLE = bytes([99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22])
INV_SB_TABLE = bytes([82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251, 124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203, 84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78, 8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37, 114, 248, 246, 100, 134, 104, 152, 22, 212, 164, 92, 204, 93, 101, 182, 146, 108, 112, 72, 80, 253, 237, 185, 218, 94, 21, 70, 87, 167, 141, 157, 132, 144, 216, 171, 0, 140, 188, 211, 10, 247, 228, 88, 5, 184, 179, 69, 6, 208, 44, 30, 143, 202, 63, 15, 2, 193, 175, 189, 3, 1, 19, 138, 107, 58, 145, 17, 65, 79, 103, 220, 234, 151, 242, 207, 206, 240, 180, 230, 115, 150, 172, 116, 34, 231, 173, 53, 133, 226, 249, 55, 232, 28, 117, 223, 110, 71, 241, 26, 113, 29, 41, 197, 137, 111, 183, 98, 14, 170, 24, 190, 27, 252, 86, 62, 75, 198, 210, 121, 32, 154, 219, 192, 254, 120, 205, 90, 244, 31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95, 96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239, 160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97, 23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125])
SR_TABLE = bytes([0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11])
INV_SR_TABLE = bytes([0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3])
ROUND_CONSTANTS = bytes([0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36])

#FUNCTIONS FOR AES
class AES_primitives:
    #Sub bytes
    def SB(block: bytes) -> bytes:
        '''Sub Bytes primitive for AES'''
        assert(len(block) == 16)
        return bytes([(SB_TABLE[block[i]]) for i in range(16)])

    #Inverse sub bytes
    def inv_SB(block: bytes) -> bytes:
        '''Inverse Sub Bytes primitive for AES'''
        assert(len(block) == 16)
        return bytes([(INV_SB_TABLE[block[i]]) for i in range(16)])

    #Shift rows
    def SR(block: bytes) -> bytes:
        '''Shift Rows primitive for AES'''
        assert(len(block) == 16)
        return bytes([(block[SR_TABLE[i]]) for i in range(16)])

    #Inverse shift rows
    def inv_SR(block: bytes) -> bytes:
        '''Inverse Shift Rows primitive for AES'''
        assert(len(block) == 16)
        return bytes([(block[INV_SR_TABLE[i]]) for i in range(16)])
        
    #HELPER METHOD TO MULTIPLY FOR MC
    def multiply(b, a):
        tmp = (a<<1) & 0xff
        match b:
            case 1: return a
            case 2: return tmp if a < 128 else tmp^0x1b
            case 3: return tmp^a if a < 128 else (tmp^0x1b)^a

    #Mix Columns
    def MC(block: bytes) -> bytes:
        '''Mix Columns primitive for AES'''
        output = bytearray(16)
        mar = [2, 1, 1, 3, 3, 2, 1, 1, 1, 3, 2, 1, 1, 1, 3, 2] #mix-columns array
        #mix the columns
        for i in range(16):
            row, col = i & 0x3, i >> 2
            folder = bytearray([(AES_primitives.multiply(mar[j * 4 + row], block[col * 4 + j])) for j in range(4)])
            output[i] = folder[0] ^ folder[1] ^ folder[2] ^ folder[3]
        return bytes(output)

    #Inverse mix columns
    def inv_MC(block: bytes) -> bytes:
        '''Inverse Mix Columns primitive for AES'''
        return AES_primitives.MC(AES_primitives.MC(AES_primitives.MC(block)))

    #Add Round Key
    def ARK(block: bytes, round_key: bytes) -> bytes:
        '''Add Round Key primitive for AES'''
        assert(len(block) == 16 and len(round_key) == 16)
        return bytes(map(lambda x, y : x ^ y, block, round_key))

    #Invert add round key
    def inv_ARK(block: bytes, round_key: bytes) -> bytes:
        '''Inverse Add Round Key primitive for AES'''
        return AES_primitives.ARK(block, AES_primitives.inv_MC(round_key))

    #Padding function
    def pad_block(data: bytes) -> bytes:
        pad_len = 16 - (len(data) & 0xF)
        data = bytearray(data)
        data.extend(bytearray([(pad_len) for i in range(pad_len)]))
        return bytes(data)

    def validate_PKCS7_Padding(buf : bytes) -> bool:
        #Check length is compliant.
        #Must be non-zero multiple of 16 as padding is at least one byte.
        if len(buf) % 16 or len(buf) == 0: return False

        #Get the pad length, check validity
        pad_implied_size = buf[-1]
        if pad_implied_size > 16 or pad_implied_size == 0: return False


        #Check the rest of the pad's implied length.
        for i in range(-1, -1-pad_implied_size, -1):
            if buf[i] != pad_implied_size: return False
        
        #No other fails, passes verification.
        return True

    def trim_pkcs7_padding(buf : bytes) -> bool:
        assert(AES_primitives.validate_PKCS7_Padding(buf))
        pad_implied_size = buf[-1]
        return bytes(buf[:0-pad_implied_size])

    #Round Key Extension Function
    def run_key_schedule(keybytes: bytes) -> list[bytes]:
        #initialize key schedule column
        key_columns = [(keybytes[i * 4: (i + 1) * 4]) for i in range(4)]

        #Generate rows for keys
        for i in range(4, 4 * (NUM_ROUNDS) + 4):
            #Load the base value for the column
            new_column = bytearray(key_columns[i-4])
            prev_column = bytearray(key_columns[i-1])

            #Compute new column
            if not (i & 0x3):
                #Compute T(W(i-1)) 
                shifted_column = bytearray([prev_column[(i + 1) & 0x3] for i in range(4)])
                subbed_column = bytearray([(SB_TABLE[shifted_column[i]]) for i in range(4)])
                t_column = bytearray([subbed_column[0] ^ ROUND_CONSTANTS[(i-4)//4], subbed_column[1], subbed_column[2], subbed_column[3]])
                prev_column = bytearray(t_column)

            #Append 
            key_columns.append(bytes([(new_column[j] ^ prev_column[j]) for j in range(4)]))  
        return key_columns

    def get_round_keys(initial_key: bytes) -> list[bytes]:
        #Generate the Rijndael Key Schedule and then chunkify it.
        key_table = AES_primitives.run_key_schedule(initial_key)
        round_key_list = []
        for i in range(NUM_ROUNDS+ 1):
            arkey = bytearray()
            for j in range(4):
                arkey.extend(key_table[4*i + j])
            round_key_list.append(bytes(arkey))
        return round_key_list

    #Rounds functions. Saves some code.
    def encrypt_round(block: bytes, round_key: bytes) -> bytes:
        return AES_primitives.ARK(AES_primitives.MC(AES_primitives.SR(AES_primitives.SB(block))),round_key)
    def decrypt_round(block: bytes, round_key: bytes) -> bytes:
        return AES_primitives.inv_ARK(AES_primitives.inv_MC(AES_primitives.inv_SR(AES_primitives.inv_SB(block))),round_key)
    def encrypt_final_round(block: bytes, round_key: bytes) -> bytes:
        return AES_primitives.ARK(AES_primitives.SR(AES_primitives.SB(block)),round_key)
    def decrypt_final_round(block: bytes, round_key: bytes) -> bytes:
        return AES_primitives.ARK(AES_primitives.inv_SR(AES_primitives.inv_SB(block)),round_key)

    #Block Encryption Function (Can be used for any mode such as ECB, CBC, or CTR)
    def encrypt_block_128(block: bytes, aes_key: bytes) -> bytes:
        round_keys = AES_primitives.get_round_keys(aes_key)
        output = AES_primitives.ARK(block, round_keys[0])
        for i in range(1,10): output = AES_primitives.encrypt_round(output, round_keys[i])
        return AES_primitives.encrypt_final_round(output, round_keys[10])

    def decrypt_block_128(block: bytes, aes_key: bytes) -> bytes:
        round_keys = AES_primitives.get_round_keys(aes_key)
        output = AES_primitives.ARK(block, round_keys[10])
        for i in range(9,0,-1): output = AES_primitives.decrypt_round(output, round_keys[i])
        return AES_primitives.decrypt_final_round(output,round_keys[0])

#Main Encryption Functions for ECB128
class AES_ECB_128:
    def encrypt(data: bytes, aes_key: bytes):
        output = bytearray()
        padded = False
        round_keys = AES_primitives.get_round_keys(aes_key)
        while not padded:
            if len(data) < 16:
                data = AES_primitives.pad_block(data)
                padded = True
            new_block = data[:16] #Grab the next block in plaintext form
            data = data[16:] #Trim the data
            new_block = AES_primitives.ARK(new_block, round_keys[0])
            for i in range(1,10): new_block = AES_primitives.encrypt_round(new_block, round_keys[i])
            output.extend(AES_primitives.encrypt_final_round(new_block, round_keys[10]))
        return bytes(output)

    def decrypt(data: bytes, aes_key: bytes):
        output = bytearray()
        if (len(data) & 0xF): raise Exception("Ciphertext length is not a multiple of 16 bytes")
        round_keys = AES_primitives.get_round_keys(aes_key)
        while len(data):
            new_block = data[:16]
            data = data[16:]
            new_block = AES_primitives.ARK(new_block, round_keys[10])
            for i in range(9,0,-1): new_block = AES_primitives.decrypt_round(new_block, round_keys[i]) 
            new_block = AES_primitives.decrypt_final_round(new_block, round_keys[0])
            if len(data) == 0: new_block = AES_primitives.trim_pkcs7_padding(new_block)
            output.extend(new_block)
        return bytes(output)

#Main 
if __name__ == "__main__":
    with open("challdata/7.txt", "r") as f:
        from base64 import b64decode
        ciphertext = b64decode("".join([x.strip() for x in f.readlines()]))
        KEY = bytes("YELLOW SUBMARINE","utf-8")
        plain_bytes = AES_ECB_128.decrypt(ciphertext, KEY)
        print(plain_bytes.decode("ascii"))