
def var_int_len(value):
    """ Calculates the length of a variable integer. """
    if value <= 0xFF:
        return 1
    elif value <= 0xFFFF:
        return 2
    elif value <= 0xFFFFFFFF:
        return 4
    else:
        return 8

def var_int_to_bytes(value):
    """ Converts a variable integer to bytes. """
    if value <= 0xFF:
        return value.to_bytes(1, byteorder='big')
    elif value <= 0xFFFF:
        return value.to_bytes(2, byteorder='big')
    elif value <= 0xFFFFFFFF:
        return value.to_bytes(4, byteorder='big')
    else:
        return value.to_bytes(8, byteorder='big')

def read_var_int(buf):
    """ Reads a variable-length integer from the buffer. """
    first_byte = buf.read(1)[0]
    if first_byte <= 0xFF:
        return first_byte
    elif first_byte <= 0xFFFF:
        return int.from_bytes(buf.read(1), byteorder='big', signed=False) + (first_byte << 8)
    elif first_byte <= 0xFFFFFFFF:
        return int.from_bytes(buf.read(3), byteorder='big', signed=False) + (first_byte << 24)
    else:
        return int.from_bytes(buf.read(7), byteorder='big', signed=False) + (first_byte << 56)
