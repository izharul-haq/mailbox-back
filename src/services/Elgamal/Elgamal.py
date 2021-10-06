from math import ceil
from random import randint
from typing import Union


def encrypt(message: bytes, y: int, g: int, p: int) -> bytes:
    '''Encrypt given message with saved public key (g, y, p)
    using Elgamal algorithm.'''

    res: list[bytes] = []

    k: int = randint(1, p - 2)
    chunk_size: int = ceil(p.bit_length() / 8) - 1

    for i in range(0, len(message), chunk_size):
        chunk: bytes = message[i:i + chunk_size]

        a: int = pow(g, k, p)
        b: int = pow(int.from_bytes(chunk, byteorder='big') * pow(y, k), 1, p)

        res.append(
            a.to_bytes(chunk_size + 1, byteorder='big')
            + b.to_bytes(chunk_size + 1, byteorder='big')
        )

    return b''.join(res)


def decrypt(cipher: Union[bytes, list[int]], x: int, p: int) -> bytes:
    '''Decrypt given cipher with saved private key (x, p) 
    using Elgamal algorithm.'''

    res: list[bytes] = []

    chunk_size: int = ceil(p.bit_length() / 8)

    if type(cipher) == bytes:
        for i in range(0, len(cipher), 2 * chunk_size):
            a: bytes = cipher[i: i + chunk_size]
            b: bytes = cipher[i + chunk_size: i + 2 * chunk_size]

            a_inv: int = pow(int.from_bytes(a, byteorder='big'), p - 1 - x, p)
            message: int = (int.from_bytes(b, byteorder='big') * a_inv) % p

            res.append(message.to_bytes(chunk_size - 1, byteorder='big'))

    else:
        for i in range(0, len(cipher), 2):
            a = cipher[i]
            b = cipher[i+1]

            a_inv: int = pow(a, p - 1 - x, p)
            message: int = (b * a_inv) % p

            res.append(message.to_bytes(chunk_size - 1, byteorder='big'))

    return b''.join(res)
