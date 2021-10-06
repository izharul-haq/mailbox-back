from typing import Union


def generate_key(key_type: str, p: int, g: int, x: int) -> tuple:
    '''Generate Elgamal public/private key using given prime number p
    and random number g and x.

    It's assumed that g < p and 1 <= x <= p - 2.'''

    y = pow(g, x, p)

    if key_type == 'public':
        return (y, g, p)

    else:   # key_type == 'private'
        return (x, p)
