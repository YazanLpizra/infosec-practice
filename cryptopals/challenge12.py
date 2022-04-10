import secrets

from challenge7 import encrypt_aes_ecb
from challenge8 import is_aes_ecb
from challenge10 import cipher_block_chaining
from challenge11 import encryption_oracle
from base64 import b64decode

def gen_rand_bytes(num_bytes: int = 16) -> bytes:
    return secrets.token_bytes(num_bytes)

def encryption_oracle(input_str: str, key: bytes = None) -> bytes:
    # prefix_bytes = gen_rand_bytes(secrets.choice(range(5,11)))
    # suffix_bytes = gen_rand_bytes(secrets.choice(range(5,11)))
    # plaintext_bytes = prefix_bytes + input_str.encode('utf8') + suffix_bytes

    prefix_bytes = b"""Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK"""

    # plaintext_bytes = prefix_bytes + input_str.encode('utf8')
    plaintext_bytes = input_str.encode('utf8')

    if key is None:
        key = gen_rand_bytes(16)

    ciphertext = encrypt_aes_ecb(plaintext_bytes, key)

    return ciphertext

def ecb_replay_attack(plaintext: bytes):
    block_size = 1
    for i in range(1, 100):
        block_size = i
        buffer = plaintext[0] * i
        # print(res)

if __name__ == '__main__':
    key = b"YELLOW SUBMARINE"
    print(encryption_oracle('a', key))