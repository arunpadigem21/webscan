import os
# Importing the libraries
import sys
import argparse
import subprocess
import os
import time
import random
import threading
import re
import random
from urllib.parse import urlsplit
import pyfiglet

def check_internet():
    os.system('ping -c1 google.com > rs_net 2>&1')  # Change to google.com
    if "0% packet loss" in open('rs_net').read():
        val = 1  # Internet is available
    else:
        val = 0  # Internet is not available
    os.system('rm rs_net > /dev/null 2>&1')  # Clean up the temporary file
    return val

# Scan Time Elapser
intervals = (
    ('h', 3600),
    ('m', 60),
    ('s', 1),
    )
def display_time(seconds, granularity=3):
    result = []
    seconds = seconds + 1
    for name, count in intervals:
        value = seconds // count
        if value:
            seconds -= value * count
            result.append("{}{}".format(value, name))
    return ' '.join(result[:granularity])


def terminal_size():
    try:
        rows, columns = subprocess.check_output(['stty', 'size']).split()
        return int(columns)
    except subprocess.CalledProcessError as e:
        return int(20)
    


def url_maker(url):
    if not re.match(r'http(s?)\:', url):
        url = 'http://' + url
    parsed = urlsplit(url)
    host = parsed.netloc
    if host.startswith('www.'):
        host = host[4:]
    return host