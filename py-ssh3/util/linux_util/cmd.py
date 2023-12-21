import pty
import subprocess
import os

def start_with_size_and_pty(command, args, ws, login_shell=False):
    master, slave = pty.openpty()
    if ws:
        pty.set_winsize(master, ws[0], ws[1])
    
    env = os.environ.copy()
    if login_shell:
        args[0] = f"-{os.path.basename(args[0])}"

    process = subprocess.Popen(args, preexec_fn=os.setsid, stdin=slave, stdout=slave, stderr=slave, env=env)
    os.close(slave)
    return process, master