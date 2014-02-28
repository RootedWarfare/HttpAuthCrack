HEADER = '\033[95m'
BLUE = '\033[94m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
ENDC = '\033[0m'
BOLD = "\033[1m"

globals()["_debug"] = 0

def debug(val):
    globals()["_debug"] = val

def disable():
    HEADER = ''
    OKBLUE = ''
    OKGREEN = ''
    WARNING = ''
    FAIL = ''
    ENDC = ''

def success(msg):
    print GREEN + msg + ENDC

def info(msg):
    if (_debug == 1):
        print BLUE + msg + ENDC

def warn(msg):
    if (_debug == 1):
        print YELLOW + msg + ENDC

def err(msg):
    if (_debug == 1):
        print RED + msg + ENDC
