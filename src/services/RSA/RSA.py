from math import ceil
from typing import Union


def encrypt(message: bytes, e: int, n: int) -> bytes:
    '''Encrypt given message using saved public key
    with RSA algorithm.'''

    res: list[bytes] = []

    chunk_size: int = ceil((n.bit_length()) / 8) - 1

    for i in range(0, len(message), chunk_size):
        chunk: bytes = message[i:i + chunk_size]

        cipher: int = pow(int.from_bytes(chunk, byteorder='big'), e, n)

        res.append(cipher.to_bytes(chunk_size + 1, byteorder='big'))

    return b''.join(res)


def decrypt(message: Union[bytes, list[int]], d: int, n: int) -> bytes:

    res: list[bytes] = []

    chunk_size: int = ceil((n.bit_length()) / 8)

    if type(message) == bytes:
        for i in range(0, len(message), chunk_size):
            chunk: bytes = message[i:i + chunk_size]

            cipher: int = pow(int.from_bytes(chunk, byteorder='big'), d, n)

            res.append(cipher.to_bytes(chunk_size - 1, byteorder='big'))

    else:
        for number in message:
            cipher: int = pow(number, d, n)

            res.append(cipher.to_bytes(chunk_size - 1, byteorder='big'))

    return b''.join(res)
