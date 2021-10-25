def encrypt(message: bytes, g: int, n: int) -> bytes:
    '''Encrypt given message using public key (g, n)
    with Paillier algorithm.'''

    res: list[bytes] = []

    chunk_size: int = ceil((n.bit_length()) / 8) - 1

    pass


def decrypt(cipher: Union[bytes, list[int]],
            g: int, n: int, l: int, m: int) -> bytes:
    '''Decrypt given cipher using public key (g, n)
    and private key (l, m) with Paillier algorithm.'''

    res: list[bytes] = []

    chunk_size: int = ceil((n.bit_length()) / 8)

    pass
