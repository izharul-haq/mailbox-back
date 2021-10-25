from sympy import lcm
from random import randint


def generate_key(p: int, q: int) -> (int, int, int, int):
    '''Generate Paillier public/private key using given prime
    numbers p and q.

    It's assumed that both p and q are prime and both p and q
    satisfy the GCD(pq, (p-1)(q-1)) = 1.'''

    n = p * q
    square_n = n * n
    l = int(lcm(p-1, q-1))

    # maximum square_n - n is used so that there are distances
    # between g and square_n in case g needs to be corrected.
    g = randint(2, square_n-n)

    # corrects g if m doesn't exist
    while True:
        try:
            L = (pow(g, l, square_n) - 1) // n
            m = pow(L, -1, n)

            return (g, n, l, m)

        except Exception as e:
            g += 1
