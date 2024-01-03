import ctypes
from pwd import getpwnam
from crypt import crypt
import subprocess
import os
import spwd

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
    password = spwd.getspnam(name)
    return ShadowEntry(password.sp_namp, password.sp_pwdp)

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
