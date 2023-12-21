
MAJOR = 0
MINOR = 1
PATCH = 0

class InvalidSSHVersion(Exception):
    def __init__(self, version_string):
        self.version_string = version_string

    def __str__(self):
        return f"invalid ssh version string: {self.version_string}"

class UnsupportedSSHVersion(Exception):
    def __init__(self, version_string):
        self.version_string = version_string

    def __str__(self):
        return f"unsupported ssh version: {self.version_string}"

def get_current_version():
    return f"SSH 3.0 ElNiak/py-ssh3 {MAJOR}.{MINOR}.{PATCH}"

def parse_version(version):
    fields = version.split()
    if len(fields) != 4 or fields[0] != "SSH" or fields[1] != "3.0":
        raise InvalidSSHVersion(version_string=version)

    major_dot_minor = fields[3].split(".")
    if len(major_dot_minor) != 3:
        raise InvalidSSHVersion(version_string=version)

    try:
        major = int(major_dot_minor[0])
        minor = int(major_dot_minor[1])
        patch = int(major_dot_minor[2])
    except ValueError:
        raise InvalidSSHVersion(version_string=version)

    return major, minor, patch
