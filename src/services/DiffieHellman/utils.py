def generate_key(p: int, q: int, x: int, y: int) -> (int, int, int):
    '''Generate session key from given n, g, and x values.

    It's assumed that both p and q are prime numbers and p > q,
    while x and y are just random integers.'''

    X = pow(q, x, p)
    Y = pow(q, y, p)
    K = pow(Y, x, p)

    return X, Y, K
