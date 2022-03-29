"""
    Detect single-character XOR

    One of the 60-character strings in this file has been encrypted by single-character XOR.

    Find it.

    (Your code from #3 should help.)
"""

import json
from math import inf
from challenge3 import char_freq_xor_decode, chi_squared_scoring, score_text_as_lang

if __name__ == "__main__":
    with open('./english_language_charachter_frequencies.json') as lang_freq_file, open('./4.txt', 'rt') as data_file:    
        lang_freq_map = json.load(lang_freq_file)

        decode_fn = lambda hex_str: char_freq_xor_decode(bytes.fromhex(hex_str.strip()), lang_freq_map, 'utf8', chi_squared_scoring)
        results = [decode_fn(line) for line in data_file.readlines()]
        results = [r for r in results if r[0] is not inf]
        optimal_result = sorted(results, key=lambda tup: tup[0])
        print(optimal_result)
        """
        the result is:
        [
            (27.396093820508746, 'R4^Ho+[7tRO_dV)84fi##[R3LihkwG', 'e'), 
            (40.296519805563, 'Now that the party is jumping\n', '5'), // not the lowest score, but more likely to be correct
            (43.99218123708534, 'Ok*DOs8BiKeL8_guI_ro/y#Y|<3A[F', 'p'), 
            (45.051354672599096, '_ HvHm?lw@fr%1$n KeAbC9:vO@h9W', 'i'), 
            (79.42882070229494, 'qvSu}ahhu&@>d+gR4,|TGn}Al8~sCB', 'd'), 
            (92.76933967723427, 'kwb%gpl,$lXgO.OhV\t8DF|k7)M{GoN', 's'), 
            (294.7439151983607, ']$4OFs>\\YQ#\nK9y?IT4PeNWTxFqc0\r', 'g'), 
            (1180.1550432083654, 'Zf/[Xi{kczx%Gkxr]bd@(rw\rkGQKzx', 't')
        ]
        """
