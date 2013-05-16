#!/usr/bin/env python
import binascii
from fractions import Fraction
from functools import partial
import hashlib
import itertools
import json
import math
import random
import time

import Crypto.Hash.SHA as SHA
import Crypto.PublicKey.RSA as RSA
import Crypto.Signature.PKCS1_v1_5 as PKCS1_v1_5
from Crypto.Util.number import bytes_to_long, long_to_bytes, getPrime, getStrongPrime, GCD

#random.seed('matasano') #for reproducibility - will work with any seed


#http://docs.python.org/2/library/itertools.html#recipes
def grouper(n, iterable, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper(3, 'ABCDEFG', 'x') --> ABC DEF Gxx
    args = [iter(iterable)] * n
    return itertools.izip_longest(fillvalue=fillvalue, *args)


def invmod(a, b):
    m = b
    x, lastx = 0, 1
    y, lasty = 1, 0
    while b:
        q = a / b
        a, b = b, a % b
        x, lastx = lastx - q * x, x
        y, lasty = lasty - q * y, y
    return lastx % m


#http://stackoverflow.com/a/358134
def nth_root(x,n):
    """Finds the integer component of the n'th root of x,
    an integer such that y ** n <= x < (y + 1) ** n.
    """
    high = 1
    while high ** n < x:
        high *= 2
    low = high/2
    while low < high:
        mid = (low + high) // 2
        if low < mid and mid**n < x:
            low = mid
        elif high > mid and mid**n > x:
            high = mid
        else:
            return mid
    return mid + 1


def rsa_encrypt(m, e, n):
    return pow(bytes_to_long(m), e, n)


def rsa_decrypt(c, d, n):
    return long_to_bytes(pow(c, d, n))


def rsa_genkeys(bits, e):
    bits = bits / 2
    et = e
    while GCD(e, et) != 1:
        if bits < 512:
            #getStrongPrime won't accept bits < 512
            p, q = getPrime(bits), getPrime(bits)
        else:
            p, q = getStrongPrime(bits, e), getStrongPrime(bits, e)
        et = (p-1) * (q-1)

    n = p * q
    d = invmod(e, et)
    return (e,n), (d,n)


dsa_p = long(''.join("""
800000000000000089e1855218a0e7dac38136ffafa72eda7
859f2171e25e65eac698c1702578b07dc2a1076da241c76c6
2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe
ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2
b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87
1a584471bb1""".strip().split()), 16)

dsa_q = long('f4f47f05794b256174bba6e9b396a7707e563c5b', 16)

dsa_g = long(''.join("""
5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119
458fef538b8fa4046c8db53039db620c094c9fa077ef389b5
322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047
0f5b64c36b625a097f1651fe775323556fe00b3608c887892
878480e99041be601a62166ca6894bdd41a7054ec89f756ba
9fc95302291""".strip().split()), 16)


def dsa_genkeys(p, q, g):
    x = random.randrange(1, q)
    y = pow(g, x, p)
    return (p,q,g,y), x


def dsa_sign(p, q, g, x, h, leak_k=False):
    #relax constraints for problem 45
    #r, s = 0, 0
    #while r == 0 or s == 0:
    k = random.randrange(1, q)
    r = pow(g, k, p) % q
    s = (invmod(k, q) * (h + x*r)) % q
    if leak_k:
        return (r, s), k
    return r, s


def dsa_verify(pubkey, h, sig):
    p, q, g, y = pubkey
    r, s = sig
    #relax constraints for problem 45
    #if not 0 < r < q:
    #    return False
    #if not 0 < s < q:
    #    return False

    w = invmod(s, q)
    u1 = (h * w) % q
    u2 = (r * w) % q
    v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q
    return v == r


def dsa_recover_x(q, h, sig, k):
    r, s = sig
    return (((s * k) - h) * invmod(r, q) % q)


def padding_oracle(k, privkey, c):
    m = rsa_decrypt(c, *privkey)
    m = '\x00' * (k - len(m)) + m #I2OSP
    return m[:2] == '\x00\x02'


def pkcs_pad(k, m):
    if len(m) > k - 11:
        raise Exception('m is too long')
    plen = k - len(m) - 3
    pad = ''.join(chr(random.randint(1, 255)) for _ in xrange(plen))
    return ''.join(['\x00\x02', pad, '\x00', m])


def bleichencrack(fcrypt, k, pubkey, c):
    e, n = pubkey
    B = 2 ** (8 * (k-2))
    Mi = set([(2 * B, 3 * B - 1)])
    c0, si = c, 1 #skip blinding (step 1)
    for i in itertools.count(1):
        Mi_1 = Mi
        si_1 = si
        if i == 1:
            #2.a
            si = n / (3 * B)
            while not fcrypt(c0 * pow(si, e, n)):
                si += 1
            #print '%s 2.a si: %s' % (i, si)
        elif len(Mi_1) > 1:
            #2.b
            si = si_1 + 1
            while not fcrypt(c0 * pow(si, e, n)):
                si += 1
            #print '%s 2.b si: %s' % (i, si)
        else:
            #2.c
            a, b = list(Mi_1)[0]
            ri = 2 * ((b * si_1 - 2 * B) / n)
            found = False
            while not found:
                si = (2 * B + ri * n) / b
                si_hi = (3 * B + ri * n) / a
                while si <= si_hi:
                    if fcrypt(c0 * pow(si, e, n)):
                        found = True
                        break
                    si += 1
                ri += 1
            #print '%s 2.b si: %s' % (i, si)

        #3
        Mi = set()
        for a, b in Mi_1:
            r, mod = divmod(a * si - 3 * B + 1, n)
            if mod:
                r += 1
            r_hi = (b * si - 2 * B) / n
            while r <= r_hi:
                lo, mod = divmod(2 * B + r * n, si)
                if mod:
                    lo += 1
                lo = max(a, lo)
                hi = min(b, divmod(3 * B - 1 + r * n, si)[0])
                Mi.add((lo,hi))
                r += 1
        #print '%s 3 Mi: %s' % (i, Mi)

        #4
        if len(Mi) == 1:
            a, b = list(Mi)[0]
            if a == b:
                m = long_to_bytes(a)
                m = '\x00' * (k - len(m)) + m
                return m


def cc41():
    """41. Implement Unpadded Message Recovery Oracle

Nate Lawson says we should stop calling it "RSA padding" and start
calling it "RSA armoring". Here's why.

Imagine a web application, again with the Javascript encryption,
taking RSA-encrypted messages which (again: Javascript) aren't padded
before encryption at all.

You can submit an arbitrary RSA blob and the server will return
plaintext. But you can't submit the same message twice: let's say the
server keeps hashes of previous messages for some liveness interval,
and that the message has an embedded timestamp:

 {
   time: 1356304276,
   social: '555-55-5555',
 }

You'd like to capture other people's messages and use the server to
decrypt them. But when you try, the server takes the hash of the
ciphertext and uses it to reject the request. Any bit you flip in the
ciphertext irrevocably scrambles the decryption.

This turns out to be trivially breakable:

* Capture the ciphertext C

* Let N and E be the public modulus and exponent respectively

* Let S be a random number > 1 mod N. Doesn't matter what.

* C' = ((S**E mod N) * C) mod N

* Submit C', which appears totally different from C, to the server,
 recovering P', which appears totally different from P

        P'
  P = -----  mod N
        S

Oops!

(Remember: you don't simply divide mod N; you multiply by the
multiplicative inverse mod N.)

Implement that attack.
"""
    seen = set()
    keypairs = {}
    def decrypt(pubkey, C):
        h = hashlib.sha1(long_to_bytes(C)).hexdigest()
        if h in seen or pubkey not in keypairs:
            return 'ERROR'
        seen.add(h)

        privkey = keypairs[pubkey]
        return rsa_decrypt(C, *privkey)


    pubkey, privkey = rsa_genkeys(bits=1024, e=3)
    keypairs[pubkey] = privkey

    msg = json.dumps({'time': int(time.time()), 'social': '078-05-1120'})
    print 'Encrypting:', msg
    C = rsa_encrypt(msg, *pubkey)
    print 'Decrypted: ', decrypt(pubkey, C)
    print 'Replayed:  ', decrypt(pubkey, C)

    E, N = pubkey
    S = random.randint(1, N)
    C_prime = (pow(S, E, N) * C) % N

    P_prime = decrypt(pubkey, C_prime)
    P_prime = bytes_to_long(P_prime)
    P = (P_prime * invmod(S, N)) % N
    print 'Recovered: ', long_to_bytes(P)


def cc42():
    """42. Bleichenbacher's e=3 RSA Attack

RSA with an encrypting exponent of 3 is popular, because it makes the
RSA math faster.

With e=3 RSA, encryption is just cubing a number mod the public
encryption modulus:

  c = m ** 3 % n

e=3 is secure as long as we can make assumptions about the message
blocks we're encrypting. The worry with low-exponent RSA is that the
message blocks we process won't be large enough to wrap the modulus
after being cubed. The block 00:02 (imagine sufficient zero-padding)
can be "encrypted" in e=3 RSA; it is simply 00:08.

When RSA is used to sign, rather than encrypt, the operations are
reversed; the verifier "decrypts" the message by cubing it. This
produces a "plaintext" which the verifier checks for validity.

When you use RSA to sign a message, you supply it a block input that
contains a message digest. The PKCS1.5 standard formats that block as:

 00h 01h ffh ffh ... ffh ffh 00h ASN.1 GOOP HASH

As intended, the ffh bytes in that block expand to fill the whole
block, producing a "right-justified" hash (the last byte of the hash
is the last byte of the message).

There was, 7 years ago, a common implementation flaw with RSA
verifiers: they'd verify signatures by "decrypting" them (cubing them
modulo the public exponent) and then "parsing" them by looking for
00h 01h ... ffh 00h ASN.1 HASH.

This is a bug because it implies the verifier isn't checking all the
padding. If you don't check the padding, you leave open the
possibility that instead of hundreds of ffh bytes, you have only a
few, which if you think about it means there could be squizzilions of
possible numbers that could produce a valid-looking signature.

How to find such a block? Find a number that when cubed (a) doesn't
wrap the modulus (thus bypassing the key entirely) and (b) produces a
block that starts "00h 01h ffh ... 00h ASN.1 HASH".

There are two ways to approach this problem:

* You can work from Hal Finney's writeup, available on Google, of how
 Bleichenbacher explained the math "so that you can do it by hand
 with a pencil".

* You can implement an integer cube root in your language, format the
 message block you want to forge, leaving sufficient trailing zeros
 at the end to fill with garbage, then take the cube-root of that
 block.

Forge a 1024-bit RSA signature for the string "hi mom". Make sure your
implementation actually accepts the signature!
"""
    print """Note: pycrypto explicitly checks for this attack
(see https://github.com/dlitz/pycrypto/blob/master/lib/Crypto/Signature/PKCS1_v1_5.py#L159)
so this uses an intentionally broken signature verifier that doesn't check padding.
"""

    def broken_verify_rsa_sha1(msg, key, sig):
        asn1_sha1 = '\x000!0\t\x06\x05+\x0e\x03\x02\x1a\x05\x00\x04\x14'
        h = hashlib.sha1(msg).digest()

        m = key.encrypt(sig, 0)[0]
        offset = m.find('\xff\x00')+1
        asn1_hash = m[offset:offset+36]
        if asn1_hash == asn1_sha1 + h:
            return True
        return False


    msg = "hi mom"

    #generate sig with throwaway key to get asn1+hash
    key = RSA.generate(1024, e=3)
    h = SHA.new(msg)
    ss = PKCS1_v1_5.new(key)
    psig = ss.sign(h)
    raw = key.encrypt(psig, 0)[0]
    print 'Generate sig with throwaway key to get asn1+hash'
    print 'Valid Sig:', raw.encode('hex')
    print 'Verified: ', broken_verify_rsa_sha1(msg, key, psig)

    #build the new block
    asn1_hash = raw[raw.find('\xff\x00')+1:]
    prefix = '\x01' + '\xff' * 4
    suffix = '\x01' * 87
    sig = prefix + asn1_hash + suffix
    #print sig.encode('hex')
    x = bytes_to_long(sig)
    newsig = nth_root(x, 3)

    #generate new key with e=3 to test forgery
    key = RSA.generate(1024, e=3)
    print
    print 'Test forgery with new key'
    print 'Forged Sig:', long_to_bytes(newsig**3).encode('hex')
    print 'Verified: ', broken_verify_rsa_sha1(msg, key, long_to_bytes(newsig))


def cc43():
    """43. DSA Key Recovery From Nonce

Step 1: Relocate so that you are out of easy travel distance of us.

Step 2: Implement DSA, up to signing and verifying, including
parameter generation.

HAH HAH YOU'RE TOO FAR AWAY TO COME PUNCH US.

JUST KIDDING you can skip the parameter generation part if you
want; if you do, use these params:

p = 800000000000000089e1855218a0e7dac38136ffafa72eda7
    859f2171e25e65eac698c1702578b07dc2a1076da241c76c6
    2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe
    ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2
    b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87
    1a584471bb1

q = f4f47f05794b256174bba6e9b396a7707e563c5b

g = 5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119
    458fef538b8fa4046c8db53039db620c094c9fa077ef389b5
    322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047
    0f5b64c36b625a097f1651fe775323556fe00b3608c887892
    878480e99041be601a62166ca6894bdd41a7054ec89f756ba
    9fc95302291

("But I want smaller params!" Then generate them yourself.)

The DSA signing operation generates a random subkey "k". You know this
because you implemented the DSA sign operation.

This is the first and easier of two challenges regarding the DSA "k"
subkey.

Given a known "k", it's trivial to recover the DSA private key "x":

      (s * k) - H(msg)
  x = ----------------  mod q
              r

Do this a couple times to prove to yourself that you grok it. Capture
it in a function of some sort.

Now then. I used the parameters above. I generated a keypair. My
pubkey is:

   y = 84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4
       abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004
       e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed
       1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b
       bb283e6633451e535c45513b2d33c99ea17

I signed

 For those that envy a MC it can be hazardous to your health
 So be friendly, a matter of life and death, just like a etch-a-sketch

(My SHA1 for this string was d2d0714f014a9784047eaeccf956520045c45265;
I don't know what NIST wants you to do, but when I convert that hash
to an integer I get 0xd2d0714f014a9784047eaeccf956520045c45265).

I get:

   r = 548099063082341131477253921760299949438196259240
   s = 857042759984254168557880549501802188789837994940

I signed this string with a broken implemention of DSA that generated
"k" values between 0 and 2^16. What's my private key?

Its SHA-1 fingerprint (after being converted to hex) is:

 0954edd5e0afe5542a4adf012611a91912a3ec16

Obviously, it also generates the same signature for that string.
"""
    p, q, g = dsa_p, dsa_q, dsa_g
    h = 0xd2d0714f014a9784047eaeccf956520045c45265

    #test out signing/verifying
    print 'Signing/verifying hash:', hex(h)
    pubkey, x = dsa_genkeys(p, q, g)
    sig = dsa_sign(p, q, g, x, h)
    print 'Verified:', dsa_verify(pubkey, h, sig)
    print
    print 'Verifying bad hash:', hex(h+42)
    print 'Verified:', dsa_verify(pubkey, h+42, sig)
    print

    sig, k = dsa_sign(p, q, g, x, h, leak_k=True)
    print 'Leaked k:', k
    print 'Recovered x:', x
    print 'Match:', x == dsa_recover_x(q, h, sig, k)
    print

    y = long(''.join("""
84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4
abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004
e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed
1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b
bb283e6633451e535c45513b2d33c99ea17""".strip().split()), 16)

    r = 548099063082341131477253921760299949438196259240
    s = 857042759984254168557880549501802188789837994940
    x_hash = '0954edd5e0afe5542a4adf012611a91912a3ec16'

    pubkey = p, q, g, y
    sig = r, s

    for k in xrange(1, 2**16 + 1):
        rx = pow(g, k, p) % q
        if rx == r:
            break

    print 'Found k:', k
    x = dsa_recover_x(q, h, sig, k)
    print 'Recovered x:', x
    print 'Match:', x_hash == hashlib.sha1(hex(x)[2:-1]).hexdigest()


def cc44():
    """44. DSA Nonce Recovery From Repeated Nonce

At the following URL, find a collection of DSA-signed messages:

 https://gist.github.com/anonymous/f83e6b6e6889f2e8b7ff

(NB: each msg has a trailing space.)

These were signed under the following pubkey:

 y = 2d026f4bf30195ede3a088da85e398ef869611d0f68f07
     13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8
     5519b1c23cc3ecdc6062650462e3063bd179c2a6581519
     f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430
     f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3
     2971c3de5084cce04a2e147821

(using the same domain parameters as the previous exercise)

It should not be hard to find the messages for which we have
accidentally used a repeated "k". Given a pair of such messages, you
can discover the "k" we used with the following formula:

          (m1 - m2)
      k = --------- mod q
          (s1 - s2)

Remember all this math is mod q; s2 may be larger than s1, for
instance, which isn't a problem if you're doing the subtraction mod
q. If you're like me, you'll definitely lose an hour to forgetting a
paren or a mod q. (And don't forget that modular inverse function!)

What's my private key? Its SHA-1 (from hex) is:

    ca8f6f7c66fa362d40760d135b763eb8527d3d52
"""
    def gen_messages(fname): 
        with open(fname) as f:
            for lines in grouper(4, f, ''):
                msg, s, r, m = [x.strip('\n').split(':')[1][1:] for x in lines]
                yield msg, long(s), long(r), long(m, 16)


    y = long(''.join("""
2d026f4bf30195ede3a088da85e398ef869611d0f68f07
13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8
5519b1c23cc3ecdc6062650462e3063bd179c2a6581519
f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430
f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3
2971c3de5084cce04a2e147821""".strip().split()), 16)
    x_hash = 'ca8f6f7c66fa362d40760d135b763eb8527d3d52'
    p, q, g = dsa_p, dsa_q, dsa_g

    #r = pow(g, k, p) % q, so signatures with shared k will share r
    r_data = {}
    for msg1, s1, r1, m1 in gen_messages('data/cc44.txt'):
        if r1 in r_data:
            msg2, s2, m2 = r_data[r1]
            break
        r_data[r1] = msg1, s1, m1

    m = (m1 - m2) % q
    s = (s1 - s2) % q
    k = m * invmod(s, q)

    print 'Found k:', k
    x = dsa_recover_x(q, m1, (r1, s1), k)
    print 'Recovered x:', x
    print 'Match:', x_hash == hashlib.sha1(hex(x)[2:-1]).hexdigest()


def cc45():
    """45. DSA Parameter Tampering

Take your DSA code from the previous exercise. Imagine it as part of
an algorithm in which the client was allowed to propose domain
parameters (the p and q moduli, and the g generator).

This would be bad, because attackers could trick victims into accepting
bad parameters. Vaudenay gave two examples of bad generator
parameters: generators that were 0 mod p, and generators that were 1
mod p.

Use the parameters from the previous exercise, but substitute 0 for
"g". Generate a signature. You will notice something bad. Verify the
signature. Now verify any other signature, for any other string.

Now, try (p+1) as "g". With this "g", you can generate a magic
signature s, r for any DSA public key that will validate against any
string. For arbitrary z:

   r = ((y**z) % p) % q

         r
   s =  --- % q
         z

Sign "Hello, world". And "Goodbye, world".
"""
    h = 0xd2d0714f014a9784047eaeccf956520045c45265
    p, q = dsa_p, dsa_q

    g = 0
    pubkey, x = dsa_genkeys(p, q, g)
    print 'If g == 0, r will also, and any signature or hash will validate'
    print 'Signing/verifying hash:', hex(h)
    sig = dsa_sign(p, q, g, x, h)
    print '(r, s):', sig
    print 'Verified:', dsa_verify(pubkey, h, sig)
    print
    print 'Verifying bad hash:', hex(h+42)
    print 'Verified:', dsa_verify(pubkey, h+42, sig)
    r, s = sig
    print 'Verifying bad sig:', (r, s+42)
    print 'Verified:', dsa_verify(pubkey, h, (r, s+42))
    print

    g = p + 1
    pubkey, x = dsa_genkeys(p, q, g)
    y = pubkey[-1]

    def dsa_sign_magic(p, q, y, z):
        r = pow(y, z, p) % q
        s = r * invmod(z, q)
        return r, s

    for msg in ("Hello, world", "Goodbye, world"):
        h = bytes_to_long(hashlib.sha1(msg).digest())
        print 'Signing/verifying:', msg
        sig = dsa_sign_magic(p, q, y, h)
        print '(r, s):', sig
        print 'Verified:', dsa_verify(pubkey, h, sig)


def cc46():
    """46. Decrypt RSA From One-Bit Oracle

This is a bit of a toy problem, but it's very helpful for
understanding what RSA is doing (and also for why pure
number-theoretic encryption is terrifying).

Generate a 1024 bit RSA key pair.

Write an oracle function that uses the private key to answer the
question "is the plaintext of this message even or odd" (is the last
bit of the message 0 or 1). Imagine for instance a server that
accepted RSA-encrypted messages and checked the parity of their
decryption to validate them, and spat out an error if they were of the
wrong parity.

Anyways: function returning true or false based on whether the
decrypted plaintext was even or odd, and nothing else.

Take the following string and un-Base64 it in your code (without
looking at it!) and encrypt it to the public key, creating a
ciphertext:

VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==

With your oracle function, you can trivially decrypt the message.

Here's why:

* RSA ciphertexts are just numbers. You can do trivial math on
 them. You can for instance multiply a ciphertext by the
 RSA-encryption of another number; the corresponding plaintext will
 be the product of those two numbers.

* If you double a ciphertext (multiply it by (2**e)%n), the resulting
 plaintext will (obviously) be either even or odd.

* If the plaintext after doubling is even, doubling the plaintext
 DIDN'T WRAP THE MODULUS --- the modulus is a prime number. That
 means the plaintext is less than half the modulus.

You can repeatedly apply this heuristic, once per bit of the message,
checking your oracle function each time.

Your decryption function starts with bounds for the plaintext of [0,n].

Each iteration of the decryption cuts the bounds in half; either the
upper bound is reduced by half, or the lower bound is.

After log2(n) iterations, you have the decryption of the message.

Print the upper bound of the message as a string at each iteration;
you'll see the message decrypt "hollywood style".

Decrypt the string (after encrypting it to a hidden private key, duh) above.
"""
    rsa_decrypt_long = pow
    def parity_oracle(privkey, c):
        return rsa_decrypt_long(c, *privkey) & 1


    pubkey, privkey = rsa_genkeys(bits=1024, e=3)
    fcrypt = partial(parity_oracle, privkey)
    msg = 'VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=='
    msg = msg.decode('base64')
    c = rsa_encrypt(msg, *pubkey)

    e, n = pubkey
    lo, hi = Fraction(0), Fraction(n)
    for _ in xrange(int(math.log(n, 2))+1):
        c = c * pow(2, e, n)
        m = (lo + hi) / 2
        if fcrypt(c):
            lo = m
        else:
            hi = m
        print long_to_bytes(long(hi))


def cc47():
    """47. Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)

Google for:

"Chosen ciphertext attacks against protocols based on the RSA encryption standard"

This is Bleichenbacher from CRYPTO '98; I get a bunch of .ps versions
on the first search page.

Read the paper. It describes a padding oracle attack on
PKCS#1v1.5. The attack is similar in spirit to the CBC padding oracle
you built earlier; it's an "adaptive chosen ciphertext attack", which
means you start with a valid ciphertext and repeatedly corrupt it,
bouncing the adulterated ciphertexts off the target to learn things
about the original.

This is a common flaw even in modern cryptosystems that use RSA.

It's also the most fun you can have building a crypto attack. It
involves 9th grade math, but also has you implementing an algorithm
that is complex on par with finding a minimum cost spanning tree.

The setup:

*   Build an oracle function, just like you did in the last exercise, but
    have it check for plaintext[0] == 0 and plaintext[1] == 2.

*   Generate a 256 bit keypair (that is, p and q will each be 128 bit
    primes), [n, e, d].

*   Plug d and n into your oracle function.

*   PKCS1.5-pad a short message, like "kick it, CC", and call it
 "m". Encrypt to to get "c".

Decrypt "c" using your padding oracle.

For this challenge, we've used an untenably small RSA modulus (you
could factor this keypair instantly). That's because this exercise
targets a specific step in the Bleichenbacher paper --- Step 2c, which
implements a fast, nearly O(log n) search for the plaintext.

Things you want to keep in mind as you read the paper:

*   RSA ciphertexts are just numbers.

*   RSA is "homomorphic" with respect to multiplication, which
 means you can multiply c * RSA(2) to get a c' that will
    decrypt to plaintext * 2. This is mindbending but easy to
    see if you play with it in code --- try multiplying
 ciphertexts with the RSA encryptions of numbers so you know
 you grok it.

    What you need to grok for this challenge is that Bleichenbacher
    uses multiplication on ciphertexts the way the CBC oracle uses
    XORs of random blocks.

*   A PKCS#1v1.5 conformant plaintext, one that starts with 00:02,
    must be a number between 02:00:00...00 and 02:FF:FF..FF --- in
    other words, 2B and 3B-1, where B is the bit size of the
    modulus minus the first 16 bits. When you see 2B and 3B,
    that's the idea the paper is playing with.

To decrypt "c", you'll need Step 2a from the paper (the search for the
first "s" that, when encrypted and multiplied with the ciphertext,
produces a conformant plaintext), Step 2c, the fast O(log n) search,
and Step 3.

Your Step 3 code is probably not going to need to handle multiple
ranges.

We recommend you just use the raw math from paper (check, check,
double check your translation to code) and not spend too much time
trying to grok how the math works.
"""
    msg = "kick it, CC"
    bits = 256
    k = bits/8
    pubkey, privkey = rsa_genkeys(bits=bits, e=3)
    fcrypt = partial(padding_oracle, k, privkey)
    pmsg = pkcs_pad(k, msg)
    print 'Padded msg:', repr(pmsg)
    c = rsa_encrypt(pmsg, *pubkey)

    pm = bleichencrack(fcrypt, k, pubkey, c)
    print 'Recovered: ', repr(pm)
    print 'Match:', pm == pmsg


def cc48():
    """48. Bleichenbacher's PKCS 1.5 Padding Oracle (Complete)

This is a continuation of challenge #47; it implements the complete
BB'98 attack.

Set yourself up the way you did in #47, but this time generate a 768
bit modulus.

To make the attack work with a realistic RSA keypair, you need to
reproduce step 2b from the paper, and your implementation of Step 3
needs to handle multiple ranges.

The full Bleichenbacher attack works basically like this:

*   Starting from the smallest 's' that could possibly produce
    a plaintext bigger than 2B, iteratively search for an 's' that
    produces a conformant plaintext.

*   For our known 's1' and 'n', solve m1=m0s1-rn (again: just a
    definition of modular multiplication) for 'r', the number of
    times we've wrapped the modulus.

    'm0' and 'm1' are unknowns, but we know both are conformant
    PKCS#1v1.5 plaintexts, and so are between [2B,3B].

    We substitute the known bounds for both, leaving only 'r'
    free, and solve for a range of possible 'r'  values. This
    range should be small!

*   Solve m1=m0s1-rn again but this time for 'm0', plugging in
    each value of 'r' we generated in the last step. This gives
    us new intervals to work with. Rule out any interval that
    is outside 2B,3B.

*   Repeat the process for successively higher values of 's'.
    Eventually, this process will get us down to just one
    interval, whereupon we're back to exercise #47.

What happens when we get down to one interval is, we stop blindly
incrementing 's'; instead, we start rapidly growing 'r' and backing it
out to 's' values by solving m1=m0s1-rn for 's' instead of 'r' or
'm0'. So much algebra! Make your teenage son do it for you! *Note:
does not work well in practice*
"""
    msg = "kick it, CC"
    bits = 768
    k = bits/8
    pubkey, privkey = rsa_genkeys(bits=bits, e=3)
    fcrypt = partial(padding_oracle, k, privkey)
    pmsg = pkcs_pad(k, msg)
    print 'Padded msg:', repr(pmsg)
    c = rsa_encrypt(pmsg, *pubkey)

    pm = bleichencrack(fcrypt, k, pubkey, c)
    print 'Recovered: ', repr(pm)
    print 'Match:', pm == pmsg


if __name__ == '__main__':
    for f in (cc41, cc42, cc43, cc44, cc45, cc46, cc47, cc48):
        print f.__doc__.split('\n')[0]
        f()
        print

