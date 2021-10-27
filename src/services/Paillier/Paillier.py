from math import ceil
from random import randint
from typing import Union

from sympy import gcd


def encrypt(message: bytes, g: int, n: int) -> bytes:
    '''Encrypt given message using public key (g, n)
    with Paillier algorithm.'''

    res: list[bytes] = []

    # maximum square_n - n is used so that there are distances
    # between r and n in case r needs to be corrected.
    r: int = randint(0, n)
    for i in range(r, n):
        if gcd(r, n) == 1:
            break
        else:
            r = i

    square_n: int = n * n
    r_to_n = pow(r, n, square_n)

    chunk_size_1: int = ceil((n.bit_length()) / 8) - 1
    chunk_size_2: int = ceil((square_n.bit_length()) / 8)

    for i in range(0, len(message), chunk_size_1):
        chunk: bytes = message[i:i + chunk_size_1]

        cipher: int = (
            pow(g, int.from_bytes(chunk, byteorder='big'), square_n) * r_to_n
        ) % square_n

        res.append(cipher.to_bytes(chunk_size_2, byteorder='big'))

    return b''.join(res)


def decrypt(cipher: Union[bytes, list[int]],
            g: int, n: int, l: int, m: int) -> bytes:
    '''Decrypt given cipher using public key (g, n)
    and private key (l, m) with Paillier algorithm.'''

    res: list[bytes] = []

    square_n: int = n * n

    chunk_size_1: int = ceil((square_n.bit_length()) / 8)
    chunk_size_2: int = ceil((n.bit_length()) / 8) - 1

    if type(cipher) == bytes:
        for i in range(0, len(cipher), chunk_size_1):
            chunk: bytes = cipher[i:i+chunk_size_1]

            message: int = ((
                (pow(int.from_bytes(chunk, byteorder='big'), l, square_n) - 1) // n
            ) * m) % n

            res.append(message.to_bytes(chunk_size_2, byteorder='big'))

    else:
        for number in cipher:
            cipher: int = ((
                (pow(number, l, square_n) - 1) // n
            ) * m) % n

            res.append(cipher.to_bytes(chunk_size_2, byteorder='big'))

    return b''.join(res)
