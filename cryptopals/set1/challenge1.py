"""
    Convert hex to base64

    The string:

    49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d

    Should produce:

    SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t

    So go ahead and make that happen. You'll need to use this code for the rest of the exercises. 
"""

import base64

def hex_to_b64(hex_str):
    input_bytes = bytes.fromhex(hex_str)
    return base64.b64encode(input_bytes)

if __name__ == "__main__":
    input_hex_str = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    expected_b64_str = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

    actual_b64_str = hex_to_b64(input_hex_str).decode('utf8')

    try:
        assert actual_b64_str == expected_b64_str
        print('assert passed!')
    except AssertionError:
        print(f'FAILURE: Actual value [{actual_b64_str}] does not match expected value [{expected_b64_str}]')
