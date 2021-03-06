from typing import Union


def generate_key(p: int, g: int, x: int) -> (int, int, int, int):
    '''Generate Elgamal public/private key using given prime number p
    and random number g and x.

    It's assumed that g < p and 1 <= x <= p - 2.'''

    y = pow(g, x, p)

    return (y, g, x, p)
