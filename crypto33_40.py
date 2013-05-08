#!/usr/bin/env python
import sys
import hmac
from hashlib import sha1, sha256
import random
import itertools

from Crypto.Cipher import AES

random.seed('matasano') #for reproducibility - will work with any seed

nist_p = int(''.join("""
ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
fffffffffffff""".strip().split()), 16)
nist_g = 2


#modified from http://docs.python.org/2/library/itertools.html#recipes
def grouper(n, iterable, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper(3, 'ABCDEFG', 'x') --> ABC DEF Gxx
    args = [iter(iterable)] * n
    groups = itertools.izip_longest(fillvalue=fillvalue, *args)
    return (''.join(group) for group in groups)


def make_keys(p, g):
    x = random.randint(0, sys.maxint) % p
    return x, pow(g, x, p) #(g**x) % p


def random_key(keylen):
    return ''.join(chr(random.randint(0,255)) for _ in xrange(keylen))


def pkcs7_pad(blocklen, data):
    padlen = blocklen - len(data) % blocklen
    return data + chr(padlen) * padlen


class PadException(Exception):
        pass

def pkcs7_strip(data):
    padchar = data[-1]
    padlen = ord(padchar)
    if padlen == 0 or not data.endswith(padchar * padlen):
        raise PadException
    return data[:-padlen]


def aes_encrypt(key, data, mode=AES.MODE_CBC):
    iv = random_key(16)
    data = AES.new(key, IV=iv, mode=mode).encrypt(pkcs7_pad(16, data))
    iv, data = iv.encode('hex'), data.encode('hex')
    return iv, data


def aes_decrypt(key, iv, data, mode=AES.MODE_CBC):
    iv, data = iv.decode('hex'), data.decode('hex')
    return pkcs7_strip(AES.new(key, IV=iv, mode=mode).decrypt(data))


def cc33():
    """33. Implement Diffie-Hellman

For one of the most important algorithms in cryptography this exercise
couldn't be a whole lot easier.

Set "p" to 37 and "g" to 5. This algorithm is so easy I'm not even
going to explain it. Just do what I do.

Generate "a", a random number mod 37. Now generate "A", which is "g"
raised to the "a" power mode 37 --- A = (g**a) % p.

Do the same for "b" and "B".

"A" and "B" are public keys. Generate a session key with them; set
"s" to "B" raised to the "a" power mod 37 --- s = (B**a) % p.

Do the same with A**b, check that you come up with the same "s".

To turn "s" into a key, you can just hash it to create 128 bits of
key material (or SHA256 it to create a key for encrypting and a key
for a MAC).

Ok that was fun, now repeat the exercise with bignums like in the real
world. Here are parameters NIST likes:

p:
ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
fffffffffffff

g: 2

This is very easy to do in Python or Ruby or other high-level
languages that auto-promote fixnums to bignums, but it isn't "hard"
anywhere.

Note that you'll need to write your own modexp (this is blackboard
math, don't freak out), because you'll blow out your bignum library
raising "a" to the 1024-bit-numberth power. You can find modexp
routines on Rosetta Code for most languages.
"""
    p, g = nist_p, nist_g
    #p, g = 37, 5
    print 'p:', p
    print 'g:', g
    print

    a, A = make_keys(p, g)
    b, B = make_keys(p, g)

    s1 = pow(B, a, p)
    s2 = pow(A, b, p)
    print 's1:', s1
    print 's2:', s2
    print 's1 == s2:', s1 == s2
    print

    s1key, s1mac = grouper(16, sha256('%02x' % s1).digest())
    print 'key:', s1key.encode('hex'), 'mac:', s1mac.encode('hex')


def cc34():
    """34. Implement a MITM key-fixing attack on Diffie-Hellman with
parameter injection

Use the code you just worked out to build a protocol and an
"echo" bot. You don't actually have to do the network part of this
if you don't want; just simulate that. The protocol is:

A->B            Send "p", "g", "A"
B->A            Send "B"
A->B            Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
B->A            Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv

(In other words, derive an AES key from DH with SHA1, use it in both
directions, and do CBC with random IVs appended or prepended to the
message).

Now implement the following MITM attack:

A->M            Send "p", "g", "A"
M->B            Send "p", "g", "p"
B->M            Send "B"
M->A            Send "p"
A->M            Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
M->B            Relay that to B
B->M            Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
M->A            Relay that to A

M should be able to decrypt the messages. "A" and "B" in the protocol
--- the public keys, over the wire --- have been swapped out with "p".
Do the DH math on this quickly to see what that does to the
predictability of the key.

Decrypt the messages from M's vantage point as they go by.

Note that you don't actually have to inject bogus parameters to make
this attack work; you could just generate Ma, MA, Mb, and MB as valid
DH parameters to do a generic MITM attack. But do the parameter
injection attack; it's going to come up again.
"""
    p, g = nist_p, nist_g
    #p, g = 37, 5
    def alice(p, g, msg):
        a, A = make_keys(p, g)
        B = (yield p, g, A)
        s = pow(B, a, p)
        key = sha1('%02x' % s).digest()[:16]
        iv, msg = aes_encrypt(key, msg)
        #send message to bob and get his back
        iv, msg = (yield iv, msg)
        msg = aes_decrypt(key, iv, msg)
        print 'Alice: Bob sent:', msg
        yield None


    def bob():
        p, g, A = (yield)
        b, B = make_keys(p, g)
        s = pow(A, b, p)
        key = sha1('%02x' % s).digest()[:16]
        iv, msg = (yield B)
        msg = aes_decrypt(key, iv, msg)
        print 'Bob: Alice sent:', msg
        #repeat what alice sent back to her
        iv, msg = aes_encrypt(key, msg)
        iv, msg = (yield iv, msg)


    msg = random.choice(open('/usr/share/dict/words').readlines()).strip()
    #prime the pump
    a, b = alice(p, g, msg), bob()
    a_b, _ = a.next(), b.next()
    #exchange key material and bounce msg
    while a_b:
        print '\tA->B:', a_b
        b_a = b.send(a_b)

        print '\tB->A:', b_a
        a_b = a.send(b_a)


    def mallory():
        p, g, A = (yield)
        B = (yield p, g, p)
        a_b = (yield p)
        s = 0
        key = sha1('%02x' % s).digest()[:16]
        while True:
            print 'Mallory: A->B:', aes_decrypt(key, *a_b)
            b_a = (yield a_b)

            print 'Mallory: B->A:', aes_decrypt(key, *b_a)
            a_b = (yield b_a)

    print
    print

    msg = random.choice(open('/usr/share/dict/words').readlines()).strip()
    #prime the pump
    a, m, b = alice(p, g, msg), mallory(), bob()
    a_m, _, _ = a.next(), m.next(), b.next()
    #exchange key material and bounce msg
    while a_m:
        print '\tA->M:', a_m
        m_b = m.send(a_m)

        print '\tM->B:', m_b
        b_m = b.send(m_b)

        print '\tB->M:', b_m
        m_a = m.send(b_m)

        print '\tM->A:', m_a
        a_m = a.send(m_a)


def cc35():
    """35. Implement DH with negotiated groups, and break with malicious "g" parameters

A->B            Send "p", "g"
B->A            Send ACK
A->B            Send "A"
B->A            Send "B"
A->B            Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
B->A            Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv

Do the MITM attack again, but play with "g". What happens with:

       g = 1
       g = p
       g = p - 1

Write attacks for each.
"""
    p, g = nist_p, nist_g
    #p, g = 37, 5
    def alice(p, g, msg):
        ack = (yield p, g)
        if ack != 'ACK':
            raise Exception("Bad key agreement")
        a, A = make_keys(p, g)
        B = (yield A)
        s = pow(B, a, p)
        #print 'a params:', B, a, p, g, s
        key = sha1('%02x' % s).digest()[:16]
        iv, msg = aes_encrypt(key, msg)
        #send message to bob and get his back
        iv, msg = (yield iv, msg)
        msg = aes_decrypt(key, iv, msg)
        print 'Alice: Bob sent:', msg
        yield None


    def bob():
        p, g = (yield)
        A = (yield 'ACK')
        b, B = make_keys(p, g)
        s = pow(A, b, p)
        #print 'b params:', A, b, p, g, s
        key = sha1('%02x' % s).digest()[:16]
        iv, msg = (yield B)
        msg = aes_decrypt(key, iv, msg)
        print 'Bob: Alice sent:', msg
        #repeat what alice sent back to her
        iv, msg = aes_encrypt(key, msg)
        iv, msg = (yield iv, msg)


    msg = random.choice(open('/usr/share/dict/words').readlines()).strip()
    print "No attack, msg: %s" % msg
    #prime the pump
    a, b = alice(p, g, msg), bob()
    a_b, _ = a.next(), b.next()
    #exchange key material and bounce msg
    while a_b:
        print '\tA->B:', a_b
        b_a = b.send(a_b)

        print '\tB->A:', b_a
        a_b = a.send(b_a)


    def mallory():
        p, g = (yield)
        ack = (yield p, g)
        A = (yield ack)
        B = (yield A)
        a_b = (yield B)

        if g == 1:
            s = 1
        elif g == p:
            s = 0
        elif g == p - 1:
            #TODO can we tell if s is 1 or p-1 without trying it?
            s = 1
            key = sha1('%02x' % s).digest()[:16]
            try:
                aes_decrypt(key, *a_b)
            except PadException:
                s = p - 1

        key = sha1('%02x' % s).digest()[:16]
        while True:
            print 'Mallory: A->B:', aes_decrypt(key, *a_b)
            b_a = (yield a_b)

            print 'Mallory: B->A:', aes_decrypt(key, *b_a)
            a_b = (yield b_a)

    print
    print

    for g, comment in [(1, 'g = 1'), (p, 'g = p'), (p-1, 'g = p - 1')]:
        msg = random.choice(open('/usr/share/dict/words').readlines()).strip()
        print 'Attack with msg: %s, %s:' % (msg, comment)
        #prime the pump
        a, m, b = alice(p, g, msg), mallory(), bob()
        a_m, _, _ = a.next(), m.next(), b.next()
        #exchange key material and bounce msg
        while a_m:
            print '\tA->M:', a_m
            m_b = m.send(a_m)

            print '\tM->B:', m_b
            b_m = b.send(m_b)

            print '\tB->M:', b_m
            m_a = m.send(b_m)

            print '\tM->A:', m_a
            a_m = a.send(m_a)
        print


def cc36():
    """36. Implement Secure Remote Password

To understand SRP, look at how you generate an AES key from DH; now,
just observe you can do the "opposite" operation an generate a numeric
parameter from a hash. Then:

Replace A and B with C and S (client & server)

C & S           Agree on N=[NIST Prime], g=2, k=3, I (email), P (password)
S               1. Generate salt as random integer
               2. Generate string xH=SHA256(salt|password)
               3. Convert xH to integer x somehow (put 0x on hexdigest)
               4. Generate v=g**x % N
               5. Save everything but x, xH
C->S            Send I, A=g**a % N (a la Diffie Hellman)
S->C            Send salt, B=kv + g**b % N
S, C            Compute string uH = SHA256(A|B), u = integer of uH
C               1. Generate string xH=SHA256(salt|password)
               2. Convert xH to integer x somehow (put 0x on hexdigest)
               3. Generate S = (B - k * g**x)**(a + u * x) % N
               4. Generate K = SHA256(S)
S               1. Generate S = (A * v**u) ** b % N
               2. Generate K = SHA256(S)
C->S            Send HMAC-SHA256(K, salt)
S->C            Send "OK" if HMAC-SHA256(K, salt) validates

You're going to want to do this at a REPL of some sort; it may take a
couple tries.

It doesn't matter how you go from integer to string or string to
integer (where things are going in or out of SHA256) as long as you do
it consistently. I tested by using the ASCII decimal representation of
integers as input to SHA256, and by converting the hexdigest to an
integer when processing its output.

This is basically Diffie Hellman with a tweak of mixing the password
into the public keys. The server also takes an extra step to avoid storing
an easily crackable password-equivalent.
"""
    p, g = nist_p, nist_g
    #p, g = 37, 5
    def client(N, g, k, I, P):
        a, A = make_keys(N, g)
        salt, B = (yield I, A)

        uH = sha256(str(A) + str(B)).hexdigest()
        u = int(uH, 16)

        xH = sha256(salt + P).hexdigest()
        x = int(xH, 16)
        S = pow(B - k * pow(g, x, N), a + u * x, N)
        K = sha256(str(S)).hexdigest()
        h = hmac.new(K, salt, sha256).hexdigest()
        ok = (yield h)
        print 'Login OK' if ok == 'OK' else 'Login Failed'
        yield None


    def make_credential(N, g, P):
        salt = random_key(16)
        xH = sha256(salt + P).hexdigest()
        x = int(xH, 16)
        v = pow(g, x, N)
        return salt, v


    def server(N, g, k, credentials):
        I, A = (yield)
        salt, v = credentials[I]
        b, B = make_keys(N, g)
        B += k * v
        h = (yield salt, B)

        uH = sha256(str(A) + str(B)).hexdigest()
        u = int(uH, 16)
        S = pow(A * pow(v, u, N), b, N)
        K = sha256(str(S)).hexdigest()
        yield 'OK' if h == hmac.new(K, salt, sha256).hexdigest() else 'FAIL'


    email, password = 'mc@hammer.com', '2legit2quit'
    credentials = {email: make_credential(p, g, password)}
    #prime the pump
    c, s = client(p, g, 3, email, password), server(p, g, 3, credentials)
    c_s, _ = c.next(), s.next()
    while c_s:
        print '\tC->S:', c_s
        s_c = s.send(c_s)

        print '\tS->C:', s_c
        c_s = c.send(s_c)


def cc37():
    """37. Break SRP with a zero key

Get your SRP working in an actual client-server setting. "Log in" with
a valid password using the protocol.

Now log in without your password by having the client send 0 as its
"A" value. What does this to the "S" value that both sides compute?

Now log in without your password by having the client send N, N*2, &c.
"""
    p, g = nist_p, nist_g
    #p, g = 37, 5
    def client_A(N, g, k, I, A):
        salt, B = (yield I, A)
        K = sha256(str(0)).hexdigest()
        h = hmac.new(K, salt, sha256).hexdigest()
        ok = (yield h)
        print 'Login OK' if ok == 'OK' else 'Login Failed'
        yield None


    def make_credential(N, g, P):
        salt = random_key(16)
        xH = sha256(salt + P).hexdigest()
        x = int(xH, 16)
        v = pow(g, x, N)
        return salt, v


    def server(N, g, k, credentials):
        I, A = (yield)
        salt, v = credentials[I]
        b, B = make_keys(N, g)
        B += k * v
        h = (yield salt, B)

        uH = sha256(str(A) + str(B)).hexdigest()
        u = int(uH, 16)
        S = pow(A * pow(v, u, N), b, N)
        #print 'S s:', S
        K = sha256(str(S)).hexdigest()
        yield 'OK' if h == hmac.new(K, salt, sha256).hexdigest() else 'FAIL'


    email, password = 'mc@hammer.com', '2legit2quit'
    credentials = {email: make_credential(p, g, password)}

    for A,comment in [(0, '0'), (p, 'N'), (p*2, 'N*2'), (p*3, 'N*42')]:
        print 'Attack with A == %s:' % comment
        #prime the pump
        c, s = client_A(p, g, 3, email, A), server(p, g, 3, credentials)
        c_s, _ = c.next(), s.next()
        while c_s:
            print '\tC->S:', c_s
            s_c = s.send(c_s)

            print '\tS->C:', s_c
            c_s = c.send(s_c)
        print

    print """
Sending A == 0 or an even multiple of N forces server's S to be 0 as well."""


def cc38():
    """38. Offline dictionary attack on simplified SRP

S               x = SHA256(salt|password)
               v = g**x % n
C->S            I, A = g**a % n
S->C            salt, B = g**b % n, u = 128 bit random number
C               x = SHA256(salt|password)
               S = B**(a + ux) % n
               K = SHA256(S)
S               S = (A * v ** u)**b % n
               K = SHA256(S)
C->S            Send HMAC-SHA256(K, salt)
S->C            Send "OK" if HMAC-SHA256(K, salt) validates

Note that in this protocol, the server's "B" parameter doesn't depend
on the password (it's just a Diffie Hellman public key).

Make sure the protocol works given a valid password.

Now, run the protocol as a MITM attacker: pose as the server and use
arbitrary values for b, B, u, and salt.

Crack the password from A's HMAC-SHA256(K, salt).
"""


def cc39():
    """39. Implement RSA

There are two annoying things about implementing RSA. Both of them
involve key generation; the actual encryption/decryption in RSA is
trivial.

First, you need to generate random primes. You can't just agree on a
prime ahead of time, like you do in DH. You can write this algorithm
yourself, but I just cheat and use OpenSSL's BN library to do the
work.

The second is that you need an "invmod" operation (the multiplicative
inverse), which is not an operation that is wired into your
language. The algorithm is just a couple lines, but I always lose an
hour getting it to work.

I recommend you not bother with primegen, but do take the time to get
your own EGCD and invmod algorithm working.

Now:

- Generate 2 random primes. We'll use small numbers to start, so you
can just pick them out of a prime table. Call them "p" and "q".

- Let n be p * q. Your RSA math is modulo n.

- Let et be (p-1)*(q-1) (the "totient"). You need this value only for
keygen.

- Let e be 3.

- Compute d = invmod(e, et). invmod(17, 3120) is 2753.

Your public key is [e, n]. Your private key is [d, n].

To encrypt: c = m**e%n. To decrypt: m = c**d%n

Test this out with a number, like "42".

Repeat with bignum primes (keep e=3).

Finally, to encrypt a string, do something cheesy, like convert the
string to hex and put "0x" on the front of it to turn it into a
number. The math cares not how stupidly you feed it strings.
"""


def cc40():
    """40. Implement an E=3 RSA Broadcast attack

Assume you're a Javascript programmer. That is, you're using a
naive handrolled RSA to encrypt without padding.

Assume you can be coerced into encrypting the same plaintext
three times, under three different public keys. You can; it's
happened.

Then an attacker can trivially decrypt your message, by:

1. Capturing any 3 of the ciphertexts and their corresponding pubkeys

2. Using the CRT to solve for the number represented by the three
ciphertexts (which are residues mod their respective pubkeys)

3. Taking the cube root of the resulting number

The CRT says you can take any number and represent it as the
combination of a series of residues mod a series of moduli. In the
three-residue case, you have:

result =
  (c_0 * m_s_0 * invmod(m_s_0, n_0)) +
  (c_1 * m_s_1 * invmod(m_s_1, n_1)) +
  (c_2 * m_s_2 * invmod(m_s_2, n_2)) mod N_012

where:

  c_0, c_1, c_2 are the three respective residues mod
  n_0, n_1, n_2

  m_s_n (for n in 0, 1, 2) are the product of the moduli
  EXCEPT n_n --- ie, m_s_1 is n_0 * n_2

  N_012 is the product of all three moduli

To decrypt RSA using a simple cube root, leave off the
final modulus operation; just take the raw accumulated result and
cube-root it.
"""


if __name__ == '__main__':
    for f in (cc33, cc34, cc35, cc36, cc37, cc38, cc39, cc40):
        print f.__doc__.split('\n')[0]
        f()
        print

