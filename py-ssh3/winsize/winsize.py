import os
import fcntl
import termios
import struct
from common import WindowSize

def get_winsize_unix():
    ws = WindowSize()
    try:
        packed = fcntl.ioctl(0, termios.TIOCGWINSZ, struct.pack('HHHH', 0, 0, 0, 0))
        rows, cols, xpix, ypix = struct.unpack('HHHH', packed)
        ws = WindowSize(nrows=rows, ncols=cols, pixel_width=xpix, pixel_height=ypix)
    except Exception as e:
        print(f"Error getting window size: {e}")
    return ws
