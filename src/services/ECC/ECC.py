import random
from os import urandom
from typing import Callable, Tuple

from .utils import Point, Curve

def encrypt(curve: Curve, plaintext: bytes, public_key: Point,
                      randfunc: Callable = None) -> Tuple[Point, Point]:
        
    M = curve.encode_point(plaintext)
    randfunc = randfunc or urandom
    G = curve.G
    random.seed(randfunc(1024))
    k = random.randint(1, curve.n)
    C1 = k * G
    C2 = M + k * public_key
    return C1, C2

def decrypt(curve: Curve, private_key: int, C1: Point, C2: Point) -> bytes:
    M = C2 + (curve.n - private_key) * C1
    return curve.decode_point(M)

# def decrypt(n: int, private_key: int, C1: Point, C2: Point) -> bytes:
#     M = C2 + (n - private_key) * C1
#     return decode_point(M)


# P256 = Curve(
#     a=-3,
#     b=41058363725152142129326129780047268409114441015993725554835256314039467401291,
#     p=115792089210356248762697446949407573530086143415290314195533631308867097853951,
#     n=115792089210356248762697446949407573529996955224135760342422259061068512044369,
#     G_x=48439561293906451759052585252797914202762949526041747995844080717082404635286,
#     G_y=36134250956749795798585127919587881956611106672985015071877198253568414405109)

# plaintext = b"aku"
# pri_key, pub_key = generate_key(P256)
# C1, C2 = encrypt(P256, plaintext, pub_key)
# new_plaintext = decrypt(0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551, pri_key, C1, C2)
# print(pri_key)
# print(pub_key)
# print(plaintext)
# print(new_plaintext)