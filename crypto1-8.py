#!/usr/bin/env python
import itertools
import string

from Crypto.Cipher import AES

def xor_data(key, data):
    "xor key with data, repeating key as necessary"
    if len(key) == 1:
        #shortcut
        key = ord(key)
        return ''.join(chr(ord(x) ^ key) for x in data)

    stream = itertools.cycle(key)
    return ''.join(chr(ord(x) ^ ord(y)) for x,y in itertools.izip(data, stream))


ok = set(string.letters + ' ')
def score_ratio(s):
    "ratio of letters+space to total length"
    count = sum(1 for x in s if x in ok)
    return count / float(len(s))


def score_decodings(keys, fscore, data):
    "return list of decodings, scored by fscore"
    scores = []
    for key in keys:
        plain = xor_data(key, data)
        score = fscore(plain)
        scores.append((score, key, plain))
    return sorted(scores, reverse=True)


#http://docs.python.org/2/library/itertools.html#recipes
def grouper(n, iterable, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper(3, 'ABCDEFG', 'x') --> ABC DEF Gxx
    args = [iter(iterable)] * n
    return itertools.izip_longest(fillvalue=fillvalue, *args)


def pairwise(iterable):
    "s -> (s0,s1), (s1,s2), (s2, s3), ..."
    a, b = itertools.tee(iterable)
    next(b, None)
    return itertools.izip(a, b)


def mean(lst):
    """mean(lst) -> the arithmetic mean of the values in LST"""
    return sum(lst) / float(len(lst))


def hamming(s1, s2):
    "count bits that are different (i.e. xor == 1)"
    return sum(bin(ord(x) ^ ord(y)).count('1') for x,y in zip(s1, s2))


def gen_distances(maxlen, blockcount, fdist, ciphertext):
    "for each keysize, yield mean of distances for first blockcount blocks"
    for keysize in xrange(1, maxlen+1):
        blocks = list(grouper(keysize, ciphertext))
        distances = [fdist(s1, s2) / float(keysize) for s1, s2 in pairwise(blocks[:blockcount])]
        yield mean(distances), keysize


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
    """5. Repeating-key XOR Cipher

Write the code to encrypt the string:

 Burning 'em, if you ain't quick and nimble
 I go crazy when I hear a cymbal

Under the key "ICE", using repeating-key XOR. It should come out to:

 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f

Encrypt a bunch of stuff using your repeating-key XOR function. Get a
feel for it.
"""
    output = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'

    plain = """Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""

    cipher = xor_data('ICE', plain).encode('hex')
    print 'Match' if cipher == output else 'No Match'
    print 'ICE: %s...' % cipher[:64]
    for key in ('BABY', 'FOREVER'):
        print '%s: %s...' % (key, xor_data(key, plain).encode('hex')[:64])


def cc6():
    """6. Break repeating-key XOR

The buffer at the following location:

https://gist.github.com/3132752

is base64-encoded repeating-key XOR. Break it.

Here's how:

a. Let KEYSIZE be the guessed length of the key; try values from 2 to
(say) 40.

b. Write a function to compute the edit distance/Hamming distance
between two strings. The Hamming distance is just the number of
differing bits. The distance between:

 this is a test

and:

 wokka wokka!!!

is 37.

c. For each KEYSIZE, take the FIRST KEYSIZE worth of bytes, and the
SECOND KEYSIZE worth of bytes, and find the edit distance between
them. Normalize this result by dividing by KEYSIZE.

d. The KEYSIZE with the smallest normalized edit distance is probably
the key. You could proceed perhaps with the smallest 2-3 KEYSIZE
values. Or take 4 KEYSIZE blocks instead of 2 and average the
distances.

e. Now that you probably know the KEYSIZE: break the ciphertext into
blocks of KEYSIZE length.

f. Now transpose the blocks: make a block that is the first byte of
every block, and a block that is the second byte of every block, and
so on.

g. Solve each block as if it was single-character XOR. You already
have code to do this.

e. For each block, the single-byte XOR key that produces the best
looking histogram is the repeating-key XOR key byte for that
block. Put them together and you have the key.
"""
    with open('data/cc6.txt') as f:
        ciphertext = f.read().decode('base64')

    #print hamming('this is a test', 'wokka wokka!!!') == 37
    distances = sorted(gen_distances(40, 5, hamming, ciphertext))
    #print distances[:4]
    #[(2.25, 2), (2.5999999999999996, 5), (2.818965517241379, 29), (2.8333333333333335, 3)]
    #tried first few manually - 29 wins
    #zip(*matrix) will transpose
    blocks = zip(*grouper(29, ciphertext, '\00'))
    blocks = [''.join(block) for block in blocks]
    keys = [chr(x) for x in xrange(256)]

    key = []
    for block in blocks:
        best = score_decodings(keys, score_ratio, block)[0]
        key.append(best[1])

    key = ''.join(key)
    print xor_data(key, ciphertext)
    print "Key: '%s'" % key


def cc7():
    """7. AES in ECB Mode

The Base64-encoded content at the following location:

   https://gist.github.com/3132853

Has been encrypted via AES-128 in ECB mode under the key

   "YELLOW SUBMARINE".

(I like "YELLOW SUBMARINE" because it's exactly 16 bytes long).

Decrypt it.

Easiest way:

Use OpenSSL::Cipher and give it AES-128-ECB as the cipher.
"""
    with open('data/cc7.txt') as f:
        ciphertext = f.read().decode('base64')
    print AES.new("YELLOW SUBMARINE", mode=AES.MODE_ECB).decrypt(ciphertext)


def cc8():
    """8. Detecting ECB

At the following URL are a bunch of hex-encoded ciphertexts:

  https://gist.github.com/3132928

One of them is ECB encrypted. Detect it.

Remember that the problem with ECB is that it is stateless and
deterministic; the same 16 byte plaintext block will always produce
the same 16 byte ciphertext.
"""
    with open('data/cc8.txt') as f:
        for i, line in enumerate(f):
            blocks = grouper(16, line.strip().decode('hex'))
            blockset = set()
            for block in blocks:
                if block in blockset:
                    print 'ECB in line %d: %s...' % (i+1, line[:64])
                    break
                blockset.add(block)


if __name__ == '__main__':
    for f in (cc1, cc2, cc3, cc4, cc5, cc6, cc7, cc8):
        print f.__doc__.split('\n')[0]
        f()
        print

