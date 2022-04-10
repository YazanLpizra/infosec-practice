"""
    The Base64-encoded content in this file has been encrypted via AES-128 in ECB mode under the key

    "YELLOW SUBMARINE".

    (case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW SUBMARINE" because it's exactly 16 bytes long, and now you do too).

    Decrypt it. You know the key, after all.

    Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher. 
"""
import base64

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from challenge6 import chunk_text
from challenge9 import pkcs7_padding


def encrypt_aes_ecb(plaintext: bytes, key: bytes) -> bytes:
    algorithm = algorithms.AES(key)
    cipher = Cipher(algorithm, mode=modes.ECB())
    encryptor = cipher.encryptor()

    block_size = len(key)
    plain_chunks = chunk_text(plaintext, block_size)
    cipher_chunks = [encryptor.update(pkcs7_padding(chunk, block_size)) for chunk in plain_chunks]

    return b''.join(cipher_chunks)

def decrypt_aes_ecb(ciphertext: bytes, key: bytes) -> bytes:
    algorithm = algorithms.AES(key)
    cipher = Cipher(algorithm, mode=modes.ECB())
    decryptor = cipher.decryptor()

    cipher_chunks = chunk_text(ciphertext, len(key))
    plain_chunks = [decryptor.update(chunk) for chunk in cipher_chunks]

    return b''.join(plain_chunks)

class Tests:
    def get_gettysberg_address():
        address = """ 
            Four score and seven years ago our fathers brought forth on this continent, a new nation, conceived in Liberty, and dedicated to the proposition that all men are created equal.
            Now we are engaged in a great civil war, testing whether that nation, or any nation so conceived and so dedicated, can long endure. We are met on a great battle-field of that war. We have come to dedicate a portion of that field, as a final resting place for those who here gave their lives that that nation might live. It is altogether fitting and proper that we should do this.
            But, in a larger sense, we can not dedicate we can not consecrate we can not hallow this ground. The brave men, living and dead, who struggled here, have consecrated it, far above our poor power to add or detract. The world will little note, nor long remember what we say here, but it can never forget what they did here. It is for us the living, rather, to be dedicated here to the unfinished work which they who fought here have thus far so nobly advanced. It is rather for us to be here dedicated to the great task remaining before us that from these honored dead we take increased devotion to that cause for which they gave the last full measure of devotion that we here highly resolve that these dead shall not have died in vain that this nation, under God, shall have a new birth of freedom and that government of the people, by the people, for the people, shall not perish from the earth.
        """
        return ''.join([line.strip() for line in address.splitlines()])

    def test_ecb():
        expected_plaintext = Tests.get_gettysberg_address() # 1450 chars long
        plaintext_bytes = expected_plaintext.encode('utf-8')

        key = b"YELLOW SUBMARINE"

        ciphertext = encrypt_aes_ecb(plaintext_bytes, key)

        actual_plaintext_bytes = decrypt_aes_ecb(ciphertext, key)
        actual_plaintext = actual_plaintext_bytes.decode('utf8')
        
        try:
            assert actual_plaintext.startswith(expected_plaintext)
            print('test_ecb test passed!')
        except AssertionError:
            print(f'FAILURE: Actual value \n[{actual_plaintext}]\n does not match expected value \n[{expected_plaintext}]')   

if __name__ == "__main__":
    Tests.test_ecb()
    
    with open('./7.txt', 'rt') as data_file:    
        encoded_text = data_file.read().strip()
        ciphertext = base64.b64decode(encoded_text)

        key = "YELLOW SUBMARINE"
        key = bytes(key, 'utf8')
        
        plaintext_bytes = decrypt_aes_ecb(ciphertext, key)
        plaintext = plaintext_bytes.decode('utf8')

        print("plaintext: ")
        print(plaintext)
