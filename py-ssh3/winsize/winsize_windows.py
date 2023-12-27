import ctypes
from ctypes import wintypes
from winsize.common import WindowSize

class CONSOLE_SCREEN_BUFFER_INFO(ctypes.Structure):
    _fields_ = [("dwSize", wintypes._COORD),
                ("dwCursorPosition", wintypes._COORD),
                ("wAttributes", wintypes.WORD),
                ("srWindow", wintypes.SMALL_RECT),
                ("dwMaximumWindowSize", wintypes._COORD)]

def get_winsize_windows():
    ws = WindowSize()
    h_std_out = ctypes.windll.kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
    csbi = CONSOLE_SCREEN_BUFFER_INFO()
    ctypes.windll.kernel32.GetConsoleScreenBufferInfo(h_std_out, ctypes.byref(csbi))
    ws.ncols, ws.nrows = csbi.srWindow.Right - csbi.srWindow.Left + 1, csbi.srWindow.Bottom - csbi.srWindow.Top + 1
    return ws
