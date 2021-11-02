from os import urandom
from abc import ABC
from dataclasses import dataclass
from typing import Optional
from binascii import hexlify
from typing import Callable, Tuple

@dataclass
class Point:
    x: Optional[int]
    y: Optional[int]
    curve: "Curve"

    def is_at_infinity(self) -> bool:
        return self.x is None and self.y is None
    def __post_init__(self):
        if not self.is_at_infinity() and not self.curve.is_on_curve(self):
            raise ValueError("The point is not on the curve.")

    def __str__(self):
        if self.is_at_infinity():
            return f"Point(At infinity, Curve={str(self.curve)})"
        else:
            return f"Point(X={self.x}, Y={self.y}, Curve={str(self.curve)})"

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other):
        return self.curve == other.curve and self.x == other.x and self.y == other.y

    def __neg__(self):
        return self.curve.neg_point(self)

    def __add__(self, other):
        return self.curve.add_point(self, other)

    def __radd__(self, other):
        return self.__add__(other)

    def __sub__(self, other):
        negative = - other
        return self.__add__(negative)

    def __mul__(self, scalar: int):
        return self.curve.mul_point(scalar, self)

    def __rmul__(self, scalar: int):
        return self.__mul__(scalar)


@dataclass
class Curve(ABC):
    a: int
    b: int
    p: int
    n: int
    G_x: int
    G_y: int

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other):
        return (
            self.a == other.a and self.b == other.b and self.p == other.p and
            self.n == other.n and self.G_x == other.G_x and self.G_y == other.G_y
        )

    @property
    def G(self) -> Point:
        return Point(self.G_x, self.G_y, self)

    @property
    def INF(self) -> Point:
        return Point(None, None, self)

    def is_on_curve(self, P: Point) -> bool:
        if P.curve != self:
            return False
        return P.is_at_infinity() or self._is_on_curve(P)

    def _is_on_curve(self, P: Point) -> bool:
        left = P.y * P.y
        right = (P.x * P.x * P.x) + (self.a * P.x) + self.b
        return (left - right) % self.p == 0

    def add_point(self, P: Point, Q: Point) -> Point:
        if (not self.is_on_curve(P)) or (not self.is_on_curve(Q)):
            raise ValueError("The points are not on the curve.")
        if P.is_at_infinity():
            return Q
        elif Q.is_at_infinity():
            return P

        if P == Q:
            return self._double_point(P)
        if P == -Q:
            return self.INF

        return self._add_point(P, Q)

    def _add_point(self, P: Point, Q: Point) -> Point:
        delta_x = P.x - Q.x
        delta_y = P.y - Q.y
        s = delta_y * modinv(delta_x, self.p)
        res_x = (s * s - P.x - Q.x) % self.p
        res_y = (P.y + s * (res_x - P.x)) % self.p
        return - Point(res_x, res_y, self)

    def double_point(self, P: Point) -> Point:
        if not self.is_on_curve(P):
            raise ValueError("The point is not on the curve.")
        if P.is_at_infinity():
            return self.INF

        return self._double_point(P)

    def _double_point(self, P: Point) -> Point:
        s = (3 * P.x * P.x + self.a) * modinv(2 * P.y, self.p)
        res_x = (s * s - 2 * P.x) % self.p
        res_y = (P.y + s * (res_x - P.x)) % self.p
        return - Point(res_x, res_y, self)

    def mul_point(self, d: int, P: Point) -> Point:
        if not self.is_on_curve(P):
            raise ValueError("The point is not on the curve.")
        if P.is_at_infinity():
            return self.INF
        if d == 0:
            return self.INF

        res = None
        is_negative_scalar = d < 0
        d = -d if is_negative_scalar else d
        tmp = P
        while d:
            if d & 0x1 == 1:
                if res:
                    res = self.add_point(res, tmp)
                else:
                    res = tmp
            tmp = self.double_point(tmp)
            d >>= 1
        if is_negative_scalar:
            return -res
        else:
            return res

    def neg_point(self, P: Point) -> Point:
        if not self.is_on_curve(P):
            raise ValueError("The point is not on the curve.")
        if P.is_at_infinity():
            return self.INF

        return self._neg_point(P)

    def _neg_point(self, P: Point) -> Point:
        return Point(P.x, -P.y % self.p, self)

    def compute_y(self, x) -> int:
        right = (x * x * x + self.a * x + self.b) % self.p
        y = modsqrt(right, self.p)
        return y

    def encode_point(self, plaintext: bytes) -> Point:
        plaintext = len(plaintext).to_bytes(1, byteorder="big") + plaintext
        while True:
            
            x = int.from_bytes(plaintext, "big")
            y = self.compute_y(x)

            if y:
                return Point(x, y, self)
            plaintext += urandom(1)

    def decode_point(self, M: Point) -> bytes:
        byte_len = int_length_in_byte(M.x)
        plaintext_len = (M.x >> ((byte_len - 1) * 8)) & 0xff
        plaintext = ((M.x >> ((byte_len - plaintext_len - 1) * 8))
                     & (int.from_bytes(b"\xff" * plaintext_len, "big")))
        return plaintext.to_bytes(plaintext_len, byteorder="big")



def egcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y

def modinv(a, m):
    a = a % m
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception("modular inverse does not exist")
    else:
        return x % m

def modsqrt(a, p):
    """ Find a quadratic residue (mod p) of 'a'. p
    must be an odd prime.
    Solve the congruence of the form:
    x^2 = a (mod p)
    And returns x.
    """

    if legendre_symbol(a, p) != 1:
        return 0
    elif a == 0:
        return 0
    elif p == 2:
        return p
    elif p % 4 == 3:
        return pow(a, (p + 1) // 4, p)

    s = p - 1
    e = 0

    while s % 2 == 0:
        s //= 2
        e += 1

    n = 2
    while legendre_symbol(n, p) != -1:
        n += 1

    x = pow(a, (s + 1) // 2, p)
    b = pow(a, s, p)
    g = pow(n, s, p)
    r = e

    while True:
        t = b
        m = 0
        for m in range(r):
            if t == 1:
                break
            t = pow(t, 2, p)

        if m == 0:
            return x

        gs = pow(g, 2 ** (r - m - 1), p)
        g = (gs * gs) % p
        x = (x * gs) % p
        b = (b * g) % p
        r = m


def legendre_symbol(a, p):
    """ Compute the Legendre symbol a|p using
    Euler's criterion. p is a prime, a is
    relatively prime to p (if p divides
    a, then a|p = 0)
    Returns 1 if a has a square root modulo
    p, -1 otherwise.
    """
    ls = pow(a, (p - 1) // 2, p)
    return -1 if ls == p - 1 else ls



def gen_keypair(curve: Curve,
                randfunc: Callable = None) -> Tuple[int, Point]:
    randfunc = randfunc or urandom
    private_key = gen_private_key(curve, randfunc)
    public_key = get_public_key(private_key, curve)
    return private_key, public_key

def gen_private_key(curve: Curve,
                    randfunc: Callable = None) -> int:
    order_bits = 0
    order = curve.n

    while order > 0:
        order >>= 1
        order_bits += 1

    order_bytes = (order_bits + 7) // 8
    extra_bits = order_bytes * 8 - order_bits

    rand = int(hexlify(randfunc(order_bytes)), 16)
    rand >>= extra_bits

    while rand >= curve.n:
        rand = int(hexlify(randfunc(order_bytes)), 16)
        rand >>= extra_bits

    return rand

def get_public_key(d: int, curve: Curve) -> Point:
    return d * curve.G

def int_length_in_byte(n: int):
    assert n >= 0
    length = 0
    while n:
        n >>= 8
        length += 1
    return length