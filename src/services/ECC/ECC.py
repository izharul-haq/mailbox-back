import random
from os import urandom
from typing import Callable, Tuple
from utils import Point, Curve

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
