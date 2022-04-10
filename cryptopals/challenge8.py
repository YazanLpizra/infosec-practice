"""
    Detect AES in ECB mode

    In this file are a bunch of hex-encoded ciphertexts.

    One of them has been encrypted with ECB.

    Detect it.

    Remember that the problem with ECB is that it is stateless and deterministic; the same 16 byte plaintext block will always produce the same 16 byte ciphertext.
"""
import binascii
from collections import Counter
from challenge6 import chunk_text

def is_aes_ecb(ciphertext: bytes, keysize: int = 16):
    chunks = chunk_text(ciphertext, keysize)
    chunk_freq = Counter(chunks)

    repeated_chunks = [block for (block,freq) in chunk_freq.items() if freq > 1]
    return len(repeated_chunks) > 0

def find_in_list(lines: str) -> str:
    for line in lines:
        if is_aes_ecb(binascii.unhexlify(line.strip())):
            return line
    return '--Not Found--'

if __name__ == "__main__":
    with open('./8.txt', 'rt') as data_file:
        lines = data_file.readlines()
        found = find_in_list(lines)
        print(found)
        # only line with repeated block: b'\x08d\x9a\xf7\r\xc0oO\xd5\xd2\xd6\x9ctL\xd2\x83'
        # d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a
