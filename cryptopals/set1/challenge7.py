"""
    The Base64-encoded content in this file has been encrypted via AES-128 in ECB mode under the key

    "YELLOW SUBMARINE".

    (case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW SUBMARINE" because it's exactly 16 bytes long, and now you do too).

    Decrypt it. You know the key, after all.

    Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher. 
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from challenge6 import chunk_text
import base64

def decrypt_aes_ecb(ciphertext: bytes, key: bytes) -> bytes:
    algorithm = algorithms.AES(key)
    cipher = Cipher(algorithm, mode=modes.ECB())
    decryptor = cipher.decryptor()

    cipher_chunks = chunk_text(ciphertext, len(key))
    plain_chunks = [decryptor.update(chunk) for chunk in cipher_chunks]

    return b''.join(plain_chunks)

if __name__ == "__main__":
    with open('./cryptopals/set1/7.txt', 'rt') as data_file:    
        encoded_text = data_file.read().strip()
        ciphertext = base64.b64decode(encoded_text)

        key = "YELLOW SUBMARINE"
        key = bytes(key, 'utf8')
        
        plaintext_bytes = decrypt_aes_ecb(ciphertext, key)
        plaintext = plaintext_bytes.decode('utf8')

        print("plaintext: ")
        print(plaintext)
