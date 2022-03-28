"""
    Single-byte XOR cipher

    The hex encoded string:

    1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736

    ... has been XOR'd against a single character. Find the key, decrypt the message.

    You can do this by hand. But don't: write code to do it for you.

    How? Devise some method for "scoring" a piece of English plaintext. Character frequency is a good metric. Evaluate each output and choose the one with the best score. 
"""

# useful ref: https://www.codementor.io/@arpitbhayani/deciphering-single-byte-xor-ciphertext-17mtwlzh30

import json
from math import inf
from typing import Dict
from collections import Counter

def single_byte_xor(text: bytes, key: int) -> bytes:
    return bytes([b ^ key for b in text])

def chi_squared_scoring(text: bytes, lang_freq_map: Dict) -> float:
    # ref: https://crypto.stackexchange.com/a/30259

    count = [0 for _ in range(26)]
    ignored = 0

    isUpperCase = lambda charcode: charcode >= 65 and charcode <= 90
    isLowerCase = lambda charcode: charcode >= 97 and charcode <= 122
    isNumSpecialChar = lambda charcode: charcode >= 32 and charcode <= 126 
    isWhitespace = lambda charcode: charcode == 9 or charcode == 10 or charcode == 13 ;  # TAB, CR, LF

    for charcode in text:
        if isUpperCase(charcode):
             count[charcode - 65] += 1
        elif isLowerCase(charcode):
            count[charcode - 97] += 1
        elif isNumSpecialChar(charcode):
            ignored += 1
        elif isWhitespace(charcode):
            ignored += 1
        else:
            return inf  # not printable ASCII = impossible(?)

    chi2 = 0
    text_len = len(text) - ignored
    for i in range(26):
        observed = count[i]
        expected = text_len * lang_freq_map[chr(i + 65)] # chars are uppercase in map
        difference = observed - expected
        chi2 += difference * difference / expected

    return chi2

def score_text_as_lang(text: bytes, lang_freq_map: Dict) -> float:
    len_text = len(text)
    text_char_counter = Counter(text)

    text_freq_map = {lang_char: (text_char_counter[ord(lang_char)] * 100 / len_text) for lang_char in lang_freq_map}
    deltas = [abs(a - b) for a, b in zip(lang_freq_map.values(), text_freq_map.values())]
    return sum(deltas) / len_text

def char_freq_xor_decode(cipher_bytes: bytes, lang_freq_map: Dict, encoding, score_fn):
    
    optimal = (inf, None, None)

    for key in range(256):
        text = single_byte_xor(cipher_bytes, key)
        score = score_fn(text, lang_freq_map)

        (best_score, _, _) = optimal
        if score < best_score:
            optimal = (score, text.decode(encoding), chr(key))
    return optimal

if __name__ == "__main__":
    with open('./cryptopals/set1/english_language_charachter_frequencies.json') as lang_freq_file:    
        input_hex_str = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
        lang_freq_map = json.load(lang_freq_file)
        
        cipher_bytes = bytes.fromhex(input_hex_str)
        decoded_result = char_freq_xor_decode(cipher_bytes, lang_freq_map, 'utf8', chi_squared_scoring)
        
        print('decoded value:', decoded_result[1]) # 'cOOKINGmcSLIKEAPOUNDOFBACON'
        print('decoding key:', decoded_result[2]) # 'x'
