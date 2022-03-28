"""
    Implement repeating-key XOR

    Here is the opening stanza of an important work of the English language:

    Burning 'em, if you ain't quick and nimble
    I go crazy when I hear a cymbal

    Encrypt it, under the key "ICE", using repeating-key XOR.

    In repeating-key XOR, you'll sequentially apply each byte of the key; the first byte of plaintext will be XOR'd against I, the next C, the next E, then I again for the 4th byte, and so on.

    It should come out to:

    0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
    a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f

    Encrypt a bunch of stuff using your repeating-key XOR function. Encrypt your mail. Encrypt your password file. Your .sig file. Get a feel for it. I promise, we aren't wasting your time with this.
"""

from challenge2 import fixed_hex_xor


# ref: https://stackoverflow.com/a/3391106
def repeat_to_length(s: str, wanted: int) -> str:
    return (s * (wanted//len(s) + 1))[:wanted]

def text_xor(text: str, key: str) -> str:
    repeated_key = None
    len_key = len(key)
    len_text = len(text)

    if len_key > len_text:
        repeated_key = key[:len_text]
    elif len_text > len_key:
        repeated_key = repeat_to_length(key, len(text))
    else:
        repeated_key = key

    hex_text = text.encode("utf-8").hex()
    hex_key = repeated_key.encode("utf-8").hex()
    return fixed_hex_xor(hex_text, hex_key)
    

if __name__ == "__main__":
    input_text = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    input_key = 'ICE'

    actual = text_xor(input_text, input_key)
    expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

    try:
        assert actual == expected
        print('assert passed!')
    except AssertionError:
        print(f'FAILURE: Actual value [{actual}] does not match expected value [{expected}]')
