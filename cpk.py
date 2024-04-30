from Crypto.Util import number

''' Congruent Public Key Algorithm '''
''' by Karl Zander '''

def isqrt(n):
  x = n
  y = (x + n // x) // 2
  while y < x:
    x = y
    y = (x + n // x) // 2
  return x

def gen_modulus(psize):
    return number.getRandomNBitInteger(psize)

def gen_priv_key(modulus):
    q2 = modulus // 2
    q4 = modulus // 4
    q2sqrt = isqrt(q2)
    q4sqrt = isqrt(q4)
    priv_key = number.getRandomRange(1, q2sqrt - 1)
    priv_modulus = number.getRandomRange(1, q2sqrt - 1)
    while (number.GCD(priv_key, priv_modulus) != 1) and priv_modulus > q4sqrt:
        priv_modulus = number.getRandomRange(1, q2sqrt - 1)
    return priv_key, priv_modulus

def gen_pub_key(priv_key, priv_modulus, modulus):
    return (number.inverse(priv_key, modulus) * priv_modulus) % modulus

def encrypt(msg, pub_key, modulus):
    q2 = modulus // 2
    q2sqrt = isqrt(q2)
    r = number.getRandomRange(1, q2sqrt - 1)
    return (r * pub_key + msg) % modulus

def decrypt(ctxt, priv_key, priv_modulus, modulus):
    a = (priv_key * ctxt) % modulus
    b = (number.inverse(priv_key, priv_modulus)  * a) % priv_modulus
    return b

msg = 123
modulus = gen_modulus(256)
priv_key, priv_modulus = gen_priv_key(modulus)
pub_key = gen_pub_key(priv_key, priv_modulus, modulus)
ctxt = encrypt(msg, pub_key, modulus)
ptxt = decrypt(ctxt, priv_key, priv_modulus, modulus)
print(ctxt)
print(ptxt)
