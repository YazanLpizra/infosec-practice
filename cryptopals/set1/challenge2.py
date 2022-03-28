"""
    Fixed XOR

    Write a function that takes two equal-length buffers and produces their XOR combination.

    If your function works properly, then when you feed it the string:

    1c0111001f010100061a024b53535009181c

    ... after hex decoding, and when XOR'd against:

    686974207468652062756c6c277320657965

    ... should produce:

    746865206b696420646f6e277420706c6179
"""

import sys

# ref: https://stackoverflow.com/a/29409299, encrypt2()
# more code and not as simple as a for-loop, but apparantly much faster impl
def fixed_hex_xor(hex_operand, hex_key, byteorder=sys.byteorder):
    byte_operand = bytes.fromhex(hex_operand)
    byte_key = bytes.fromhex(hex_key)
    # cool way to get the lengths to match
    byte_key = byte_key[:len(byte_operand)]
    byte_operand = byte_operand[:len(byte_key)]

    int_operand = int.from_bytes(byte_operand, byteorder)
    int_key = int.from_bytes(byte_key, byteorder)

    int_cipher = int_operand ^ int_key

    bytes_cipher = int_cipher.to_bytes(len(byte_key), byteorder)
    return bytes.hex(bytes_cipher)

if __name__ == "__main__":
    input_hex_str = '1c0111001f010100061a024b53535009181c'
    input_hex_key = '686974207468652062756c6c277320657965'
    expected_xor_val = '746865206b696420646f6e277420706c6179'

    actual_xor_val = fixed_hex_xor(input_hex_str, input_hex_key)
    print('actual value:', actual_xor_val)

    try:
        assert actual_xor_val == expected_xor_val
        print('assert passed!')
    except AssertionError:
        print(f'FAILURE: Actual value [{actual_xor_val}] does not match expected value [{expected_xor_val}]')
