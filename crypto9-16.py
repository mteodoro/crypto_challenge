#!/usr/bin/env python
from functools import partial
import itertools
import random

from Crypto.Cipher import AES

def random_key(keylen):
    return ''.join(chr(random.randint(0,255)) for _ in xrange(keylen))


def pkcs7_pad(blocklen, data):
    padlen = blocklen - len(data) % blocklen
    return data + chr(padlen) * padlen


def xor_block(b1, b2):
    return ''.join(chr(ord(x) ^ ord(y)) for x,y in zip(b1, b2))


#http://docs.python.org/2/library/itertools.html#recipes
def grouper(n, iterable, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper(3, 'ABCDEFG', 'x') --> ABC DEF Gxx
    args = [iter(iterable)] * n
    return itertools.izip_longest(fillvalue=fillvalue, *args)


def cbc_decrypt(key, iv, data):
    output = []
    prev_block = iv
    for block in grouper(len(key), data):
        block = ''.join(block)
        x = AES.new(key).decrypt(block)
        output.append(xor_block(prev_block, x))
        prev_block = block
    return ''.join(output)


def detect_mode(ciphertext):
    blocks = grouper(16, ciphertext)
    blockset = set()
    for block in blocks:
        if block in blockset:
            return AES.MODE_ECB
        blockset.add(block)
    return AES.MODE_CBC


def detect_blocklen(fcrypt):
    #push ciphertext over into the next block length
    orig_len = len(fcrypt(''))
    for i in xrange(1, 128):
        cur_len = len(fcrypt('A' * i))
        if cur_len - orig_len:
            blocklen = cur_len - orig_len
            return blocklen
    return -1


def cc9():
    """9. Implement PKCS#7 padding

Pad any block to a specific block length, by appending the number of
bytes of padding to the end of the block. For instance,

 "YELLOW SUBMARINE"

padded to 20 bytes would be:

 "YELLOW SUBMARINE\x04\x04\x04\x04"

The particulars of this algorithm are easy to find online.
"""
    test_data = [
            (20, 'YELLOW SUBMARINE'),
            (16, 'YELLOW SUBMARINE'),
            (8, '')]

    for padlen,data in test_data:
        print padlen, repr(data), repr(pkcs7_pad(padlen, data))


def cc10():
    """10. Implement CBC Mode

In CBC mode, each ciphertext block is added to the next plaintext
block before the next call to the cipher core.

The first plaintext block, which has no associated previous ciphertext
block, is added to a "fake 0th ciphertext block" called the IV.

Implement CBC mode by hand by taking the ECB function you just wrote,
making it encrypt instead of decrypt (verify this by decrypting
whatever you encrypt to test), and using your XOR function from
previous exercise.

DO NOT CHEAT AND USE OPENSSL TO DO CBC MODE, EVEN TO VERIFY YOUR
RESULTS. What's the point of even doing this stuff if you aren't going
to learn from it?

The buffer at:

   https://gist.github.com/3132976

is intelligible (somewhat) when CBC decrypted against "YELLOW
SUBMARINE" with an IV of all ASCII 0 (\x00\x00\x00 &c)
"""
    with open('data/cc10.txt') as f:
        ciphertext = ''.join(line for line in f).decode('base64')

    print cbc_decrypt("YELLOW SUBMARINE", '\x00' * 16, ciphertext)


def cc11():
    """11. Write an oracle function and use it to detect ECB.

Now that you have ECB and CBC working:

Write a function to generate a random AES key; that's just 16 random
bytes.

Write a function that encrypts data under an unknown key --- that is,
a function that generates a random key and encrypts under it.

The function should look like:

encryption_oracle(your-input)
=> [MEANINGLESS JIBBER JABBER]

Under the hood, have the function APPEND 5-10 bytes (count chosen
randomly) BEFORE the plaintext and 5-10 bytes AFTER the plaintext.

Now, have the function choose to encrypt under ECB 1/2 the time, and
under CBC the other half (just use random IVs each time for CBC). Use
rand(2) to decide which to use.

Now detect the block cipher mode the function is using each time.
"""
    def encryption_oracle(data):
        key = random_key(16)
        prefix = random_key(random.randint(5,10))
        suffix = random_key(random.randint(5,10))
        data = ''.join((prefix, data, suffix))

        if random.randint(0,1):
            mode = AES.MODE_ECB
            return mode, AES.new(key, mode=mode).encrypt(pkcs7_pad(16, data))
        else:
            mode = AES.MODE_CBC
            iv = random_key(16)
            return mode, AES.new(key, IV=iv, mode=mode).encrypt(pkcs7_pad(16, data))

    for i in xrange(10):
        mode, ciphertext = encryption_oracle('A' * 48)
        print i, 'ecb' if mode == AES.MODE_ECB else 'cbc',
        if mode == detect_mode(ciphertext):
            print 'Match'
        else:
            print 'No Match'


def cc12():
    """12. Byte-at-a-time ECB decryption, Full control version

Copy your oracle function to a new function that encrypts buffers
under ECB mode using a consistent but unknown key (for instance,
assign a single random key, once, to a global variable).

Now take that same function and have it append to the plaintext,
BEFORE ENCRYPTING, the following string:

 Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
 aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
 dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
 YnkK

SPOILER ALERT: DO NOT DECODE THIS STRING NOW. DON'T DO IT.

Base64 decode the string before appending it. DO NOT BASE64 DECODE THE
STRING BY HAND; MAKE YOUR CODE DO IT. The point is that you don't know
its contents.

What you have now is a function that produces:

 AES-128-ECB(your-string || unknown-string, random-key)

You can decrypt "unknown-string" with repeated calls to the oracle
function!

Here's roughly how:

a. Feed identical bytes of your-string to the function 1 at a time ---
start with 1 byte ("A"), then "AA", then "AAA" and so on. Discover the
block size of the cipher. You know it, but do this step anyway.

b. Detect that the function is using ECB. You already know, but do
this step anyways.

c. Knowing the block size, craft an input block that is exactly 1 byte
short (for instance, if the block size is 8 bytes, make
"AAAAAAA"). Think about what the oracle function is going to put in
that last byte position.

d. Make a dictionary of every possible last byte by feeding different
strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB",
"AAAAAAAC", remembering the first block of each invocation.

e. Match the output of the one-byte-short input to one of the entries
in your dictionary. You've now discovered the first byte of
unknown-string.

f. Repeat for the next byte.
"""
    def encryption_oracle(key, data):
        unknown = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK".decode('base64')
        return AES.new(key, mode=AES.MODE_ECB).encrypt(pkcs7_pad(16, data + unknown))

    key = random_key(16)
    fcrypt = partial(encryption_oracle, key)

    #detect blocklen
    blocklen = detect_blocklen(fcrypt)
    print 'Block length:', blocklen

    #detect mode
    mode = detect_mode(fcrypt('A' * 48))
    print 'Mode:', 'ecb' if mode == AES.MODE_ECB else 'cbc'

    def decrypt_block(blocklen, fcrypt, known):
        "decrypt block by passing prefixes into oracle function fcrypt"
        offset = len(known)
        plain = ''
        for i in xrange(blocklen,0,-1):
            pad = 'A' * (i - 1)
            cipher_block = fcrypt(pad)[offset:offset + blocklen]
            pad += known + plain
            for c in (chr(x) for x in xrange(256)):
                if cipher_block == fcrypt(pad + c)[offset:offset + blocklen]:
                    plain += c
                    break
        return plain

    #decrypt unknown from oracle
    cipher_blocks = len(fcrypt('')) / blocklen
    output = ''
    for _ in xrange(cipher_blocks):
        output += decrypt_block(blocklen, fcrypt, output)
    print 'Plaintext:'
    print output


def cc13():
    """13. ECB cut-and-paste

Write a k=v parsing routine, as if for a structured cookie. The
routine should take:

  foo=bar&baz=qux&zap=zazzle

and produce:

 {
   foo: 'bar',
   baz: 'qux',
   zap: 'zazzle'
 }

(you know, the object; I don't care if you convert it to JSON).

Now write a function that encodes a user profile in that format, given
an email address. You should have something like:

 profile_for("foo@bar.com")

and it should produce:

 {
   email: 'foo@bar.com',
   uid: 10,
   role: 'user'
 }

encoded as:

 email=foo@bar.com&uid=10&role=user

Your "profile_for" function should NOT allow encoding metacharacters
(& and =). Eat them, quote them, whatever you want to do, but don't
let people set their email address to "foo@bar.com&role=admin".

Now, two more easy functions. Generate a random AES key, then:

(a) Encrypt the encoded user profile under the key; "provide" that
to the "attacker".

(b) Decrypt the encoded user profile and parse it.

Using only the user input to profile_for() (as an oracle to generate
"valid" ciphertexts) and the ciphertexts themselves, make a role=admin
profile.
"""
    def kvparse(kv):
        return dict(x.split('=') for x in kv.split('&'))

    kv = 'foo=bar&baz=qux&zap=zazzle'
    print '%s: %s' % (kv, kvparse(kv))
    print

    def profile_for(email):
        email = email.translate(None, '=&')
        return 'email=%s&uid=10&role=user' % email

    for email in ('foo@bar.com', 'foo@bar.com&role=admin'):
        print '%s: %s' % (email, profile_for(email))
    print

    def encryption_oracle(key, email):
        profile = profile_for(email)
        return AES.new(key, mode=AES.MODE_ECB).encrypt(pkcs7_pad(16, profile))

    key = random_key(16)

    print "Step 1: 13-byte email forces 2nd block to end with '&role='"
    email = 'vanil@ice.com'
    print profile_for(email)
    print '^' * 32
    cipher = encryption_oracle(key, email)[:32]

    print
    print "Step 2: Create 3rd block that starts with 'admin'"
    email = 'XXXXXXXXXX' + 'admin'
    print profile_for(email)
    print ' ' * 15, '^' * 16
    cipher += encryption_oracle(key, email)[16:32]

    print
    print "Step 3: Create 4th block for proper decoding resulting in junk 'rolemail' key"
    email = 'XXXXXXXXXX'
    print profile_for(email)
    print '^' * 16
    cipher += encryption_oracle(key, email)[:16]

    plain = AES.new(key, mode=AES.MODE_ECB).decrypt(cipher)
    print
    print 'Decrypted:', plain
    print 'Parsed:', kvparse(plain)
    print


def cc14():
    """14. Byte-at-a-time ECB decryption, Partial control version

Take your oracle function from #12. Now generate a random count of
random bytes and prepend this string to every plaintext. You are now
doing:

 AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)

Same goal: decrypt the target-bytes.

What's harder about doing this?

How would you overcome that obstacle? The hint is: you're using
all the tools you already have; no crazy math is required.

Think about the words "STIMULUS" and "RESPONSE".
"""
    print """
This is harder because you have to detect the length of the prefix and pad
it out to the next blocklen so you have a clean block to use for the 
byte-by-byte decryption.

Detect full prefix blocks by seeing how many ciphertext blocks don't change
when adding a byte of data, then detect the length of the partial prefix
block by adding bytes until it doesn't change either.
"""

    def encryption_oracle(key, prefix, data):
        unknown = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK".decode('base64')
        return AES.new(key, mode=AES.MODE_ECB).encrypt(pkcs7_pad(16, prefix + data + unknown))

    key = random_key(16)
    prefix = random_key(random.randint(1,32))
    fcrypt = partial(encryption_oracle, key, prefix)

    #detect blocklen
    blocklen = detect_blocklen(fcrypt)
    print 'Block length:', blocklen

    #detect mode
    mode = detect_mode(fcrypt('A' * 48))
    print 'Mode:', 'ecb' if mode == AES.MODE_ECB else 'cbc'

    def detect_prefixlen(blocklen, fcrypt):
        #detect full prefix blocks
        prefixlen = 0
        blocks1 = grouper(blocklen, fcrypt(''))
        blocks2 = grouper(blocklen, fcrypt('A'))
        for b1,b2 in zip(blocks1, blocks2):
            if b1 != b2:
                break
            prefixlen += blocklen

        #add last (partial-block) prefix length
        offset = prefixlen
        for i in xrange(blocklen):
            b1 = fcrypt('A' * i)[offset:offset + blocklen]
            b2 = fcrypt('A' * (i + 1))[offset:offset + blocklen]
            if b1 == b2:
                prefixlen += blocklen - i
                break
        return prefixlen

    prefixlen = detect_prefixlen(blocklen, fcrypt)
    print 'Prefix length:', prefixlen

    def decrypt_block(blocklen, prefixlen, fcrypt, known):
        "decrypt block by passing prefixes into oracle function fcrypt"
        offset = 0
        while offset <= prefixlen:
            offset += blocklen
        offset += len(known)
        plain = ''
        prefix_pad = 'X' * (blocklen - prefixlen % blocklen)
        for i in xrange(blocklen,0,-1):
            pad = prefix_pad + 'A' * (i - 1)
            cipher_block = fcrypt(pad)[offset:offset + blocklen]
            pad += known + plain
            for c in (chr(x) for x in xrange(256)):
                if cipher_block == fcrypt(pad + c)[offset:offset + blocklen]:
                    plain += c
                    break
        return plain

    #decrypt unknown from oracle
    cipher_blocks = len(fcrypt('')) / blocklen
    output = ''
    for _ in xrange(cipher_blocks):
        output += decrypt_block(blocklen, prefixlen, fcrypt, output)
    print 'Plaintext:'
    print output


def cc15():
    """15. PKCS#7 padding validation

Write a function that takes a plaintext, determines if it has valid
PKCS#7 padding, and strips the padding off.

The string:

   "ICE ICE BABY\x04\x04\x04\x04"

has valid padding, and produces the result "ICE ICE BABY".

The string:

   "ICE ICE BABY\x05\x05\x05\x05"

does not have valid padding, nor does:

    "ICE ICE BABY\x01\x02\x03\x04"

If you are writing in a language with exceptions, like Python or Ruby,
make your function throw an exception on bad padding.
"""

    class PadException(Exception):
        pass

    def pkcs7_validate(data):
        padchar = data[-1]
        padlen = ord(padchar)
        if not data.endswith(padchar * padlen):
            raise PadException
        return data[:-padlen]

    test_strings = [
            "ICE ICE BABY\x04\x04\x04\x04",
            "ICE ICE BABY\x05\x05\x05\x05",
            "ICE ICE BABY\x01\x02\x03\x04",
            "ICE ICE BABY"]

    for t in test_strings:
        try:
            print '%s: %s' % (repr(t), pkcs7_validate(t))
        except PadException as e:
            print '%s: %s' % (repr(t), repr(e))


def cc16():
    """16. CBC bit flipping

Generate a random AES key.

Combine your padding code and CBC code to write two functions.

The first function should take an arbitrary input string, prepend the
string:
       "comment1=cooking%20MCs;userdata="
and append the string:
   ";comment2=%20like%20a%20pound%20of%20bacon"

The function should quote out the ";" and "=" characters.

The function should then pad out the input to the 16-byte AES block
length and encrypt it under the random AES key.

The second function should decrypt the string and look for the
characters ";admin=true;" (or, equivalently, decrypt, split the string
on ;, convert each resulting string into 2-tuples, and look for the
"admin" tuple. Return true or false based on whether the string exists.

If you've written the first function properly, it should not be
possible to provide user input to it that will generate the string the
second function is looking for.

Instead, modify the ciphertext (without knowledge of the AES key) to
accomplish this.

You're relying on the fact that in CBC mode, a 1-bit error in a
ciphertext block:

* Completely scrambles the block the error occurs in

* Produces the identical 1-bit error (/edit) in the next ciphertext
block.

Before you implement this attack, answer this question: why does CBC
mode have this property?
"""


if __name__ == '__main__':
    for f in (cc9, cc10, cc11, cc12, cc13, cc14, cc15, cc16):
        print f.__doc__.split('\n')[0]
        f()
        print

