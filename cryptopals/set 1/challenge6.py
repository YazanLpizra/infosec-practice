# from operator import is_not
# from functools import partial 
import base64
import itertools
import json
from math import inf
from typing import List
from challenge3 import char_freq_xor_decode, chi_squared_scoring, score_text_as_lang


def bits(n):
    """
        A trick for just getting the 1's out of the binary representation 
        without having to iterate over all the intervening 0's

        ref: https://stackoverflow.com/a/8898977
    """
    while n:
        b = n & (~n+1)
        yield b
        n ^= b

def hamming_distance(src_bytes: bytes, target_bytes: bytes) -> int: 
    # ref: https://en.wikipedia.org/wiki/Hamming_distance, https://www.hacksparrow.com/comp-sci/what/hamming-distance.html
    if len(src_bytes) != len(target_bytes):
        raise 'Lengths must match!'

    distance = 0
    for byte1, byte2 in zip(src_bytes, target_bytes):
        xor_val = byte1 ^ byte2
        hamming_weight = len(list(bits(xor_val))) # the number of nonzero bits in the xor val 
        distance += hamming_weight

    return distance

def chunk_text(text: str, chunk_size: int):
    # ref: https://stackoverflow.com/a/23384110
    text_len = len(text)
    return [ 
        text[i:i+chunk_size] 
        for i in range(0, text_len, chunk_size) 
    ]

def guess_keysize(ciphertext, min_keysize=2, max_keysize=40): 
    keysize_scores = [] # list of (keysize, hamming distance)
    for keysize in range(min_keysize, max_keysize):
        # calc the distance between the first 2 keysize blocks
        norm_distance1 = hamming_distance(ciphertext[0 : keysize], ciphertext[keysize : 2*keysize]) / keysize
        # calc the distance between the 3rd and 4th keysize blocks
        norm_distance2 = hamming_distance(ciphertext[0 : keysize], ciphertext[keysize : 2*keysize]) / keysize
        # average out the 2 distances
        avg_distance = (norm_distance1 + norm_distance2) / 2
        keysize_scores.append((keysize, avg_distance, ))

    # sort the keysizes by their distance score ascending 
    keysize_scores.sort(key=lambda d: d[1])

    return keysize_scores

def exclude_none(items):
    # return list(filter(partial(is_not, None), items))
    # or a more readable impl: 
    return [item for item in items if item is not None]

def viginere_decode(text: str, lang_freq_map):
    ciphertext = bytes.fromhex(base64.b64decode(text.strip()).hex())

    keysize_scores = guess_keysize(ciphertext)

    possibilities = []
    for (keysize, _) in keysize_scores[0:2]:
        chunks = chunk_text(ciphertext, keysize) # chunks of byte strings
        # we could also probably use numpy/pandas here
        # ref: https://stackoverflow.com/a/6473724
        
        transposed = list(itertools.zip_longest(*chunks, fillvalue=None)) # list of tuples of chars

        text_cols = []
        complete_key = ''
        for col in transposed:
            # join each column into a string for processing
            col_bytes = bytes(exclude_none(col))
            # process bytes
            (_, col_text, key_char) = char_freq_xor_decode(col_bytes, lang_freq_map, 'utf8', chi_squared_scoring)

            if key_char is not None:
                text_cols.append(col_text)
                complete_key += key_char

        plaintext = ''.join([''.join(items) for items in zip(*text_cols)])
        possibilities.append(plaintext)
    
    print(possibilities)



"""
    the process to guess a keysize is to brute-force a bunch of key lengths (ie: 2->40) and calculate the normalized hamming distance of substrings for each key. 
    this is useful to allow us to score keys on how consistent the distance is between keys. 
    next we need to essentally split the ciphertext into keysize-sized blocks, line up the blocks in rows, and take each column. 
    if keysize was chosen correctly, each column was encoded with the same one character and that should be easy to decode. 
    generate a char freq map for the col to detect the best key
    join up the decoded 1-char keys in order to generate the final key string        
"""
if __name__ == "__main__":

    try:
        test_str1 = bytes("this is a test", 'utf-8')
        test_str2 = bytes('wokka wokka!!!', 'utf-8')

        actual = hamming_distance(test_str1, test_str2)
        expected = 37

        assert actual == expected
        print('hamming_distance test passed!')
    except AssertionError:
        print(f'FAILURE: Actual value [{actual}] does not match expected value [{expected}]')

    with open('./english_language_charachter_frequencies.json') as lang_freq_file, open('./6.txt', 'rt') as data_file:    
        lang_freq_map = json.load(lang_freq_file)
        encoded_text = data_file.read()
        viginere_decode(encoded_text, lang_freq_map)
