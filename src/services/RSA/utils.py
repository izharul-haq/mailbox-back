from sympy import gcd


def generate_key(p: int, q: int, e: int) -> (int, int, int):
    '''Generate RSA public/private key using given prime numbers p
     and q and initial public key e.

    It's assumed that both p and q are prime while e is less than
    Φ(n) = (p - 1) * (q - 1), may or may not co-prime with Φ(n),
    and greater than one.'''

    n = p * q
    toitent = (p - 1) * (q - 1)

    step = 1 if e < n else -1

    # update e so that e is co-prime with toitent
    for i in range(e, n, step):
        if gcd(toitent, e) == 1:
            break
        else:
            e = i

    d = pow(e, -1, toitent)

    return (e, d, n)
