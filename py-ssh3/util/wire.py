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

def ReadVarInt(r):
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

def AppendVarInt(b, i):
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

def AppendVarIntWithLen(b, i, length):
    if length != 1 and length != 2 and length != 4 and length != 8:
        raise Exception("invalid varint length")
    l = VarIntLen(i)
    if l == length:
        return AppendVarInt(b, i)
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

def VarIntLen(i):
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
    length, err = ReadVarInt(buf)
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
    buf = AppendVarInt(bytearray(), len(s))
    out = out + buf
    out = out + s.encode('utf-8')
    return len(out), None

def SSHStringLen(s):
    return VarIntLen(len(s)) + len(s)

def MinUint64(a, b):
    if a <= b:
        return a
    return b
