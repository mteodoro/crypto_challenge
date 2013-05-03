#!/usr/bin/env python
import hashlib
import itertools
import random
import time

from bottle import abort, request, route, run

random.seed('matasano') #for reproducibility - will work with any seed
key = random.choice(open('/usr/share/dict/words').readlines()).strip()


def xor_block(b1, b2):
    return ''.join(chr(ord(x) ^ ord(y)) for x,y in zip(b1, b2))


def hmac_sha1(key, message):
    sha1 = lambda data: hashlib.sha1(data).digest()
    sha1_hex = lambda data: hashlib.sha1(data).hexdigest()
    if len(key) > 64:
        key = sha1(key)
    key += '\x00' * (64 - len(key))

    o_key_pad = xor_block('\x5c' * 64, key)
    i_key_pad = xor_block('\x36' * 64, key)
    return sha1_hex(o_key_pad + sha1(i_key_pad + message))


#import hmac
#tests = [('', ''), ('A' * 10, 'Ice'), ('A' * 64, 'Ice'), ('A' * 70, 'Ice')]
#for key,msg in tests:
#    hm1 = hmac_sha1(key, msg)
#    hm2 =  hmac.new(key, msg, hashlib.sha1).digest()
#    print hm1 == hm2, key, msg


def insecure_compare(sleep_secs, lhs, rhs):
    for x,y in itertools.izip_longest(lhs, rhs):
        if x != y:
            return False
        time.sleep(sleep_secs)
    return True


@route('/test31')
def test31():
    fname, sig = request.query.file, request.query.signature
    #return 'OK' if hmac_sha1(key, fname) == sig else abort(500)
    return 'OK' if insecure_compare(0.05, hmac_sha1(key, fname), sig) else abort(500)


@route('/test32')
def test32():
    fname, sig = request.query.file, request.query.signature
    #return 'OK' if hmac_sha1(key, fname) == sig else abort(500)
    return 'OK' if insecure_compare(0.005, hmac_sha1(key, fname), sig) else abort(500)


if __name__ == '__main__':
    print hmac_sha1(key, 'foo')
    run(host='localhost', port=9000, debug=True)
