import os
import tempfile

def new_unix_socket_path():
    dir = tempfile.mkdtemp(prefix="", dir="/tmp")
    return os.path.join(dir, f"agent.{os.getpid()}")