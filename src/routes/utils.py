def bytes_to_ints(b: bytes, group_size: int) -> list[int]:
    '''Grouping every bytes from given bytes by given
    group size and converting them to list of integers.'''

    res = []

    for i in range(0, len(b), group_size):
        res.append(
            int.from_bytes(b[i: i + group_size], byteorder='big')
        )

    return res
