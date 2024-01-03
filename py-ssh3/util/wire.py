import io
from message.channel_request import *
from util.type import *

# taken from the QUIC draft
Min = 0
Max = 4611686018427387903
maxVarInt1 = 63
maxVarInt2 = 16383
maxVarInt4 = 1073741823
maxVarInt8 = 4611686018427387903

# class Reader(io.ByteReader, io.Reader):
#     pass

# def NewReader(r):
#     if isinstance(r, Reader):
#         return r
#     return byteReader(r)

# class byteReader(Reader):
#     def ReadByte(self):
#         b = self.Reader.read(1)
#         if len(b) == 1:
#             return b[0], None
#         return None, io.EOF

# class Writer(io.ByteWriter, io.Writer):
#     pass

# def NewWriter(w):
#     if isinstance(w, Writer):
#         return w
#     return byteWriter(w)

# class byteWriter(Writer):
#     def WriteByte(self, c):
#         return self.Writer.write(bytes([c]))

def read_varint(r):
    firstByte, err = r.ReadByte()
    if err is not None:
        return 0, err
    length = 1 << ((firstByte & 0xc0) >> 6)
    b1 = firstByte & (0xff - 0xc0)
    if length == 1:
        return int(b1), None
    b2, err = r.ReadByte()
    if err is not None:
        return 0, err
    if length == 2:
        return int(b2) + (int(b1) << 8), None
    b3, err = r.ReadByte()
    if err is not None:
        return 0, err
    b4, err = r.ReadByte()
    if err is not None:
        return 0, err
    if length == 4:
        return int(b4) + (int(b3) << 8) + (int(b2) << 16) + (int(b1) << 24), None
    b5, err = r.ReadByte()
    if err is not None:
        return 0, err
    b6, err = r.ReadByte()
    if err is not None:
        return 0, err
    b7, err = r.ReadByte()
    if err is not None:
        return 0, err
    b8, err = r.ReadByte()
    if err is not None:
        return 0, err
    if length == 8:
        return int(b8) + (int(b7) << 8) + (int(b6) << 16) + (int(b5) << 24) + (int(b4) << 32) + (int(b3) << 40) + (int(b2) << 48) + (int(b1) << 56), None

def append_varint(b, i):
    if i <= maxVarInt1:
        return b + bytes([i])
    if i <= maxVarInt2:
        return b + bytes([(i >> 8) | 0x40, i])
    if i <= maxVarInt4:
        return b + bytes([(i >> 24) | 0x80, (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff])
    if i <= maxVarInt8:
        return b + bytes([
            (i >> 56) | 0xc0, (i >> 48) & 0xff, (i >> 40) & 0xff, (i >> 32) & 0xff,
            (i >> 24) & 0xff, (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff
        ])
    raise Exception("%x doesn't fit into 62 bits",i)

def append_varintWithLen(b, i, length):
    if length != 1 and length != 2 and length != 4 and length != 8:
        raise Exception("invalid varint length")
    l = varint_len(i)
    if l == length:
        return append_varint(b, i)
    if l > length:
        raise Exception("cannot encode %d in %d bytes", i, length)
    if length == 2:
        b = b + bytes([0b01000000])
    elif length == 4:
        b = b + bytes([0b10000000])
    elif length == 8:
        b = b + bytes([0b11000000])
    for j in range(1, length-l):
        b = b + bytes([0])
    for j in range(l):
        b = b + bytes([(i >> (8 * (l - 1 - j))) & 0xff])
    return b

def varint_len(i):
    if i <= maxVarInt1:
        return 1
    if i <= maxVarInt2:
        return 2
    if i <= maxVarInt4:
        return 4
    if i <= maxVarInt8:
        return 8
    raise Exception("value doesn't fit into 62 bits: %x",i)

def ParseSSHString(buf):
    length, err = read_varint(buf)
    if err is not None:
        return "", InvalidSSHString(err)
    out = bytearray(length)
    n, err = io.ReadFull(buf, out)
    if n != length:
        return "", InvalidSSHString("expected length %d, read length %d",length, n)
    if err is not None and err != io.EOF:
        return "", err
    return out.decode('utf-8'), err

def WriteSSHString(out, s):
    if len(out) < SSHStringLen(s):
        raise Exception("buffer too small to write varint: %d < %d", len(out), SSHStringLen(s))
    buf = append_varint(bytearray(), len(s))
    out = out + buf
    out = out + s.encode('utf-8')
    return len(out), None

def SSHStringLen(s):
    return varint_len(len(s)) + len(s)

def MinUint64(a, b):
    if a <= b:
        return a
    return b

# import struct
# import io

# # Constants for QUIC varints
# MAX_VAR_INT1 = 63
# MAX_VAR_INT2 = 16383
# MAX_VAR_INT4 = 1073741823
# MAX_VAR_INT8 = 4611686018427387903

# class ByteReader:
#     # A ByteReader class implementing io.ByteReader and io.Reader interfaces
#     def __init__(self, reader):
#         self.reader = reader

#     def read_byte(self):
#         return self.reader.read(1)

#     def read(self, n=-1):
#         return self.reader.read(n)

# def new_reader(reader):
#     # Returns a ByteReader for the given reader
#     return ByteReader(reader)

# def read_varint(reader):
#     # Read a QUIC varint from the given reader
#     first_byte = ord(reader.read_byte())
#     length = 1 << ((first_byte & 0xc0) >> 6)
#     b1 = first_byte & 0x3f
#     if length == 1:
#         return b1
#     b2 = ord(reader.read_byte())
#     if length == 2:
#         return (b2 << 8) | b1
#     b3 = ord(reader.read_byte())
#     b4 = ord(reader.read_byte())
#     if length == 4:
#         return (b4 << 24) | (b3 << 16) | (b2 << 8) | b1
#     b5 = ord(reader.read_byte())
#     b6 = ord(reader.read_byte())
#     b7 = ord(reader.read_byte())
#     b8 = ord(reader.read_byte())
#     return (b8 << 56) | (b7 << 48) | (b6 << 40) | (b5 << 32) | (b4 << 24) | (b3 << 16) | (b2 << 8) | b1

# def append_varint(b, i):
#     # Append a QUIC varint to the given byte array
#     if i <= MAX_VAR_INT1:
#         return b + struct.pack('B', i)
#     if i <= MAX_VAR_INT2:
#         return b + struct.pack('>H', i | 0x4000)
#     if i <= MAX_VAR_INT4:
#         return b + struct.pack('>I', i | 0x80000000)
#     if i <= MAX_VAR_INT8:
#         return b + struct.pack('>Q', i | 0xC000000000000000)
#     raise ValueError(f"{i} doesn't fit into 62 bits")

# def varint_len(i):
#     # Determine the number of bytes needed to write the number i
#     if i <= MAX_VAR_INT1:
#         return 1
#     if i <= MAX_VAR_INT2:
#         return 2
#     if i <= MAX_VAR_INT4:
#         return 4
#     if i <= MAX_VAR_INT8:
#         return 8
#     raise ValueError(f"value doesn't fit into 62 bits: {i}")

# def parse_ssh_string(buf):
#     # Parse an SSH string from the given buffer
#     length, _ = read_varint(buf)
#     return buf.read(length).decode('utf-8')

# def write_ssh_string(out, s):
#     # Write an SSH string to the given output buffer
#     length = len(s)
#     out.write(append_varint(b'', length))
#     out.write(s.encode('utf-8'))
#     return len(out.getvalue())

# def ssh_string_len(s):
#     # Calculate the length of an SSH string
#     return varint_len(len(s)) + len(s)

# def min_uint64(a, b):
#     # Return the minimum of two uint64 values
#     return min(a, b)
