#!/usr/bin/env python
import itertools
import string


def xor_data(key, data):
    if len(key) == 1:
        #shortcut
        key = ord(key)
        return ''.join(chr(ord(x) ^ key) for x in data)

    stream = itertools.cycle(key)
    return ''.join(chr(ord(x) ^ ord(y)) for x,y in itertools.izip(data, stream))



ok = set(string.letters + ' ')
def score_ratio(s):
    lcount = sum(1 for x in s if x in ok)
    return lcount / float(len(s))


def score_decodings(keys, fscore, data):
    scores = []
    for key in keys:
        plain = xor_data(key, data)
        score = fscore(plain)
        scores.append((score, key, plain))
    return sorted(scores, reverse=True)


def cc1():
    """1. Convert hex to base64 and back.

The string:

 49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d

should produce:

 SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t

Now use this code everywhere for the rest of the exercises. Here's a
simple rule of thumb:

 Always operate on raw bytes, never on encoded strings. Only use hex
 and base64 for pretty-printing.
"""
    s_hex = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    s_raw = s_hex.decode('hex')
    print s_raw

    s_b64 = s_raw.encode('base64')
    print s_b64.strip() #python base64 adds \n


def cc2():
    """2. Fixed XOR

Write a function that takes two equal-length buffers and produces
their XOR sum.

The string:

1c0111001f010100061a024b53535009181c

... after hex decoding, when xor'd against:

686974207468652062756c6c277320657965

... should produce:

746865206b696420646f6e277420706c6179
"""
    s1 = '1c0111001f010100061a024b53535009181c'.decode('hex')
    s2 = '686974207468652062756c6c277320657965'.decode('hex')
    s_raw = ''.join(chr(ord(x) ^ ord(y)) for x,y in zip(s1, s2))
    print s_raw
    s_hex = s_raw.encode('hex')
    print s_hex


def cc3():
    """3. Single-character XOR Cipher

The hex encoded string:

     1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736

... has been XOR'd against a single character. Find the key, decrypt
the message.

Write code to do this for you. How? Devise some method for "scoring" a
piece of English plaintext. (Character frequency is a good metric.)
Evaluate each output and choose the one with the best score.

Tune your algorithm until this works.
"""
    ciphertext = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'.decode('hex')
    keys = [chr(x) for x in xrange(256)]
    scores = score_decodings(keys, score_ratio, ciphertext)
    print "score: %.2f key: '%s' plain: %s" % scores[0]


def cc4():
    """4. Detect single-character XOR

One of the 60-character strings at:

 https://gist.github.com/3132713

has been encrypted by single-character XOR. Find it. (Your code from
#3 should help.)
"""
    keys = [chr(x) for x in xrange(256)]
    best_scores = []
    with open('data/cc4.txt') as f:
        for line in f:
            ciphertext = line.strip().decode('hex')
            scores = score_decodings(keys, score_ratio, ciphertext)
            best_scores.append(scores[0])
    best = sorted(best_scores, reverse=True)[0]
    print "score: %.2f key: '%s' plain: %s" % best


def cc5():
    """"""
    pass

def cc6():
    """"""
    pass

def cc7():
    """"""
    pass

def cc8():
    """"""
    pass


if __name__ == '__main__':
    for f in (cc1, cc2, cc3, cc4, cc5, cc6, cc7, cc8):
        print f.__doc__.split('\n')[0]
        f()
        print

