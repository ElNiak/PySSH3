import ctypes
from pwd import getpwnam
from crypt import crypt
import subprocess
import os

class User:
    def __init__(self, username, uid, gid, dir, shell):
        self.username = username
        self.uid = uid
        self.gid = gid
        self.dir = dir
        self.shell = shell
        
class ShadowEntry:
    def __init__(self, username, password):
        self.username = username
        self.password = password

def getspnam(name):
    libc = ctypes.CDLL("libc.so.6")
    size = libc.size_of_shadow()
    buf = ctypes.create_string_buffer(size)
    result = libc.getspnam_r(ctypes.c_char_p(name.encode()), buf, buf, size)
    if result != 0:
        raise ValueError("User not found")

    spwd = ctypes.cast(buf, ctypes.POINTER(ctypes.Struct_spwd)).contents
    return ShadowEntry(spwd.sp_namp.decode(), spwd.sp_pwdp.decode())

def user_password_authentication(username, password):
    shadow_entry = getspnam(username)
    return crypt(password, shadow_entry.password) == shadow_entry.password

def get_user(username):
    pw = getpwnam(username)
    return User(pw.pw_name, pw.pw_uid, pw.pw_gid, pw.pw_dir, pw.pw_shell)

def create_command(user, command, args, login_shell=False):
    # Construct subprocess command with user environment
    cmd = [command] + args
    if login_shell:
        cmd[0] = f"-{os.path.basename(command)}"
    process = subprocess.Popen(cmd, preexec_fn=os.setsid, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=user['dir'])
    return process
