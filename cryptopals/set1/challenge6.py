# from operator import is_not
# from functools import partial 
import base64
import itertools
import json
from turtle import distance
from challenge3 import char_freq_xor_decode, chi_squared_scoring
from challenge5 import text_xor

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
    chunks = [ 
        text[i:i+chunk_size] 
        for i in range(0, text_len, chunk_size) 
    ]

    # if len(chunks[-1]) != chunk_size:
    #     chunks = chunks[:-1]
    
    return chunks

def score_keysize(ciphertext, keysize):
    cipher_chunks = chunk_text(ciphertext, keysize)
    
    blocks = [
        cipher_chunks[0],
        cipher_chunks[1]
    ]

    distances = [
        [hamming_distance(block, chunk) for chunk in cipher_chunks]
        for block in blocks
    ]

    avg = (sum(distances[0]) + sum(distances[1])) / (len(cipher_chunks) * 2)
    return avg / keysize # normalize score

def guess_keysize(ciphertext, min_keysize=2, max_keysize=40): 
    keysize_scores = [] # list of (keysize, hamming distance)
    for keysize in range(min_keysize, max_keysize):
        avg_distance = score_keysize(ciphertext, keysize)
        keysize_scores.append((keysize, avg_distance, ))
        
    # sort the keysizes by their distance score ascending 
    keysize_scores.sort(key=lambda d: d[1])

    return keysize_scores[0]

def decode_multi_byte_xor(ciphertext: bytes, keysize: int, lang_freq_map):
    chunks = chunk_text(ciphertext, keysize) # chunks of byte strings
    # we could also probably use numpy/pandas here
    # ref: https://stackoverflow.com/a/6473724
    
    transposed = list(itertools.zip_longest(*chunks, fillvalue=None)) # list of tuples of chars

    text_cols = []
    complete_key = ''
    for col in transposed:
        # join each column into a string for processing
        col_bytes = bytes(col)
        # process bytes
        (_, col_text, key_char) = char_freq_xor_decode(col_bytes, lang_freq_map, 'utf8', chi_squared_scoring)

        if key_char is not None:
            text_cols.append(col_text)
            complete_key += key_char

    plaintext = ''.join([''.join(items) for items in zip(*text_cols)])
    return (plaintext, complete_key, )

def viginere_decode(text: str, lang_freq_map):
    ciphertext = bytes.fromhex(base64.b64decode(text).hex())

    (keysize, _) = guess_keysize(ciphertext)

    print('>> keysize guess:', keysize)

    return decode_multi_byte_xor(ciphertext, keysize, lang_freq_map)

class Tests:
    def get_gettysberg_address():
        address = """ 
            Four score and seven years ago our fathers brought forth on this continent, a new nation, conceived in Liberty, and dedicated to the proposition that all men are created equal.
            Now we are engaged in a great civil war, testing whether that nation, or any nation so conceived and so dedicated, can long endure. We are met on a great battle-field of that war. We have come to dedicate a portion of that field, as a final resting place for those who here gave their lives that that nation might live. It is altogether fitting and proper that we should do this.
            But, in a larger sense, we can not dedicate we can not consecrate we can not hallow this ground. The brave men, living and dead, who struggled here, have consecrated it, far above our poor power to add or detract. The world will little note, nor long remember what we say here, but it can never forget what they did here. It is for us the living, rather, to be dedicated here to the unfinished work which they who fought here have thus far so nobly advanced. It is rather for us to be here dedicated to the great task remaining before us that from these honored dead we take increased devotion to that cause for which they gave the last full measure of devotion that we here highly resolve that these dead shall not have died in vain that this nation, under God, shall have a new birth of freedom and that government of the people, by the people, for the people, shall not perish from the earth.
        """
        return ''.join([line.strip() for line in address.splitlines()])

    def test_hamming_distance():
        test_str1 = bytes("this is a test", 'utf-8')
        test_str2 = bytes('wokka wokka!!!', 'utf-8')

        actual = hamming_distance(test_str1, test_str2)
        expected = 37

        try:
            assert actual == expected
            print('hamming_distance test passed!')
        except AssertionError:
            print(f'FAILURE: Actual value [{actual}] does not match expected value [{expected}]')   

    def test_decode_multi_byte_xor_key_even_factor(lang_freq_map):
        expected_plaintext = Tests.get_gettysberg_address()
        xor_key = 'timmy'

        ciphertext = text_xor(expected_plaintext, xor_key)

        ciphertext_bytes = bytes.fromhex(ciphertext)
        actual_plaintext, actual_key = decode_multi_byte_xor(ciphertext_bytes, len(xor_key), lang_freq_map)

        try:
            assert expected_plaintext == actual_plaintext
            assert xor_key == actual_key
            print('decode_multi_byte_xor test where text_length%key_length == 0 passed!')
        except AssertionError:
            print(f'FAILURE: Actual value does not match expected value. \n>> Actual:')
            print('[', actual_plaintext, ']')
            print('>> Expected:')
            print('[', expected_plaintext, ']')

    def test_decode_multi_byte_xor_key_not_even_factor(lang_freq_map):
        expected_plaintext = Tests.get_gettysberg_address() + '.'
        xor_key = 'timmy'

        ciphertext = text_xor(expected_plaintext, xor_key)

        ciphertext_bytes = bytes.fromhex(ciphertext)
        actual_plaintext = decode_multi_byte_xor(ciphertext_bytes, len(xor_key), lang_freq_map)

        try:
            assert expected_plaintext == actual_plaintext
            print('decode_multi_byte_xor test where text_length%key_length != 0 passed!')
        except AssertionError:
            print(f'FAILURE: Actual value does not match expected value. \n>> Actual:')
            print('[', actual_plaintext, ']')
            print('>> Expected:')
            print('[', expected_plaintext, ']')
    
    """
    the process to guess a keysize is to brute-force a bunch of key lengths (ie: 2->40) and calculate the normalized hamming distance of substrings for each key. 
    this is useful to allow us to score keys on how consistent the distance is between keys. 
    next we need to essentally split the ciphertext into keysize-sized blocks, line up the blocks in rows, and take each column. 
    if keysize was chosen correctly, each column was encoded with the same one character and that should be easy to decode. 
    generate a char freq map for the col to detect the best key
    join up the decoded 1-char keys in order to generate the final key string        
"""
if __name__ == "__main__":
    with open('./cryptopals/set1/english_language_charachter_frequencies.json') as lang_freq_file, open('./cryptopals/set1/6.txt', 'rt') as data_file:    
        lang_freq_map = json.load(lang_freq_file)
        encoded_text = data_file.read().strip()
        
        print('--------- running tests ---------')
        Tests.test_hamming_distance()
        Tests.test_decode_multi_byte_xor_key_even_factor(lang_freq_map)
        # Tests.test_decode_multi_byte_xor_key_not_even_factor(lang_freq_map)
        print('--------- tests complete ---------')

        (plaintext, complete_key, ) = viginere_decode(encoded_text, lang_freq_map)
        print(f'>> complete xor key: [{complete_key}]') # "Terminator X: Bring the ioise".. "ioise" should probably be "noise"
        print(plaintext)

        # TODO: fix the chunking logic
