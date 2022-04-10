"""
    Implement CBC mode

    CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages, despite the fact that a block cipher natively only transforms individual blocks.

    In CBC mode, each ciphertext block is added to the next plaintext block before the next call to the cipher core.

    The first plaintext block, which has no associated previous ciphertext block, is added to a "fake 0th ciphertext block" called the initialization vector, or IV.

    Implement CBC mode by hand by taking the ECB function you wrote earlier, making it encrypt instead of decrypt (verify this by decrypting whatever you encrypt to test), and using your XOR function from the previous exercise to combine them.

    The file here is intelligible (somewhat) when CBC decrypted against "YELLOW SUBMARINE" with an IV of all ASCII 0 (\x00\x00\x00 &c) 
"""

from base64 import b64decode
from typing import Literal

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from challenge5 import text_xor
from challenge6 import chunk_text
from challenge9 import pkcs7_padding


def cbc_encrypt(plaintext: bytes, xor_input: bytes, encryptor):
    ciphertext = text_xor(plaintext, xor_input)
    encrypted = encryptor.update(ciphertext)
    
    return encrypted, encrypted

def cbc_decrypt(ciphertext: bytes, xor_input: bytes, decryptor):
    next_input = ciphertext
    decrypted = decryptor.update(ciphertext)
    decrypted = text_xor(decrypted, xor_input)

    return decrypted, next_input
    
def cipher_block_chaining(plaintext: bytes, key: bytes, init_vector: bytes, mode: Literal["encrypt", "decrypt"]) -> bytes:
    algorithm = algorithms.AES(key)
    cipher = Cipher(algorithm, mode=modes.ECB())
    
    cbc_fn = None
    cbc_actor = None
    
    if mode == 'decrypt':
        cbc_fn = cbc_decrypt
        cbc_actor = cipher.decryptor()
    elif mode == 'encrypt':
        cbc_fn = cbc_encrypt
        cbc_actor = cipher.encryptor()
    else:
        raise 'Invalid mode!'
    
    block_size = len(key)

    result_chunks = []
    next_input = init_vector

    chunks = chunk_text(plaintext, block_size)
    for chunk in chunks:
        chunk = pkcs7_padding(chunk, block_size)
        result, next_input = cbc_fn(chunk, next_input, cbc_actor)
        result_chunks.append(result)

    return b''.join(result_chunks)

if __name__ == "__main__":
    with open('./10.txt', 'rt') as data_file:    
        encoded_text = b64decode(data_file.read().strip())
        key = b"YELLOW SUBMARINE"
        init_vector = b"\x00" * 16

        actual = cipher_block_chaining(encoded_text, key, init_vector, 'decrypt')

        plaintext = actual.decode('utf8')

        print(plaintext)
