"""
    An ECB/CBC detection oracle

    Now that you have ECB and CBC working:

    Write a function to generate a random AES key; that's just 16 random bytes.

    Write a function that encrypts data under an unknown key --- that is, a function that generates a random key and encrypts under it.

    The function should look like:

    encryption_oracle(your-input)
    => [MEANINGLESS JIBBER JABBER]

    Under the hood, have the function append 5-10 bytes (count chosen randomly) before the plaintext and 5-10 bytes after the plaintext.

    Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC the other half (just use random IVs each time for CBC). Use rand(2) to decide which to use.

    Detect the block cipher mode the function is using each time. You should end up with a piece of code that, pointed at a block box that might be encrypting ECB or CBC, tells you which one is happening.
"""

import secrets
from typing import Literal

from challenge7 import encrypt_aes_ecb
from challenge8 import is_aes_ecb
from challenge10 import cipher_block_chaining


def gen_rand_bytes(num_bytes: int = 16) -> bytes:
    return secrets.token_bytes(num_bytes)

def encryption_oracle(input_str: str, key: bytes = None) -> bytes:
    prefix_bytes = gen_rand_bytes(secrets.choice(range(5,11)))
    suffix_bytes = gen_rand_bytes(secrets.choice(range(5,11)))
    plaintext_bytes = prefix_bytes + input_str.encode('utf8') + suffix_bytes

    if key is None:
        key = gen_rand_bytes(16)

    ciphertext = None
    mode = None

    if secrets.randbelow(2) == 0:
        mode = 'ECB'
        ciphertext = encrypt_aes_ecb(plaintext_bytes, key)
    else:
        mode = 'CBC'
        iv = gen_rand_bytes(16)
        ciphertext = cipher_block_chaining(plaintext_bytes, key, iv, 'encrypt')

    return ciphertext, mode

def is_ecb_or_cbc(ciphertext: bytes) -> Literal['ECB', 'CBC']:
    return 'ECB' if is_aes_ecb(ciphertext, 16) else 'CBC'

def get_gettysberg_address():
    address = """ 
        Four score and seven years ago our fathers brought forth on this continent, a new nation, conceived in Liberty, and dedicated to the proposition that all men are created equal.
        Now we are engaged in a great civil war, testing whether that nation, or any nation so conceived and so dedicated, can long endure. We are met on a great battle-field of that war. We have come to dedicate a portion of that field, as a final resting place for those who here gave their lives that that nation might live. It is altogether fitting and proper that we should do this.
        But, in a larger sense, we can not dedicate we can not consecrate we can not hallow this ground. The brave men, living and dead, who struggled here, have consecrated it, far above our poor power to add or detract. The world will little note, nor long remember what we say here, but it can never forget what they did here. It is for us the living, rather, to be dedicated here to the unfinished work which they who fought here have thus far so nobly advanced. It is rather for us to be here dedicated to the great task remaining before us that from these honored dead we take increased devotion to that cause for which they gave the last full measure of devotion that we here highly resolve that these dead shall not have died in vain that this nation, under God, shall have a new birth of freedom and that government of the people, by the people, for the people, shall not perish from the earth.
    """
    return ''.join([line.strip() for line in address.splitlines()])


if __name__ == "__main__":
    plaintext = 'Arbitrary data to encrypt ' * 50 #get_gettysberg_address()

    results = {
        'correct': 0,
        'incorrect': 0
    }

    for i in range(100):
        ciphertext, expected_mode = encryption_oracle(plaintext)
        actual_mode = is_ecb_or_cbc(ciphertext)
        
        res_key = 'correct' if actual_mode == expected_mode else 'incorrect'
        results[res_key] += 1

    print(results)
