"""
    Implement PKCS#7 padding

    A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of plaintext into ciphertext. But we almost never want to transform a single block; we encrypt irregularly-sized messages.

    One way we account for irregularly-sized messages is by padding, creating a plaintext that is an even multiple of the blocksize. The most popular padding scheme is called PKCS#7.

    So: pad any block to a specific block length, by appending the number of bytes of padding to the end of the block. For instance,

    "YELLOW SUBMARINE"

    ... padded to 20 bytes would be:

    "YELLOW SUBMARINE\x04\x04\x04\x04"
"""

def pkcs7_padding(src: bytes, target_len: int) -> bytes:
    delta = target_len - len(src)

    pad_byte = delta.to_bytes(1, 'big')

    return src + (pad_byte * delta)

if __name__ == "__main__":
    src_text = "YELLOW SUBMARINE"

    actual = pkcs7_padding(bytes(src_text, 'utf8'), 20)
    expected = b"YELLOW SUBMARINE\x04\x04\x04\x04"

    try:
        assert len(actual) == 20
        assert actual == expected
        print('assert passed!')
    except AssertionError:
        print(f'FAILURE: Actual value [{actual}] does not match expected value [{expected}]')
