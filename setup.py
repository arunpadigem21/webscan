#! /usr/bin/env python3
from setuptools import setup

import pathlib

# The directory containing this file
HERE = pathlib.Path(__file__).parent

# The text of the README file
README = (HERE / "README.md").read_text()

setup(
    name                =   "webscanner",
    description         =   "The Multi-Tool Web Vulnerability Scanner.",
    long_description    =   README,
    url                 =   "https://github.com/arunpadigem21/webscan",
    install_requires    =   [kali os] ,
    python_requires=">=3.6",
)
