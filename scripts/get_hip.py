"""
Simple program that reads and optionaly encrypts and/or encodes
hip-report extracted from PanGPA.log. It either print on stdout
or could save on specified file.
Author: sfgets
Licence: GPLv3
"""
import os
import sys
import re
import zlib

from pathlib import Path
from argparse import ArgumentParser, Action
from base64 import b64encode
from pyrage import passphrase

class GetPass(Action):
    """
    Helper class GetPass to handle different password inputs
    TODO: Should obfuscate the user input or suppress its output on the stdout
    """
    def __call__(self, parser, namespace, values, option_string=None):
        if os.environ.get("EPASSWORD"):
            if re.match(
                    r'^(?=.*[a-z])(?=.*\d)(?=.*[A-Z])(?=.*\W)([a-zA-Z\d\W]{8,32})$',
                    os.environ.get("EPASSWORD")
                ):
                namespace.password=os.environ.get("EPASSWORD")
            else:
                raise ValueError(r"Password is too weak")
        else:
            tmp_pass = input("Please enter password!: ")
            if tmp_pass and re.match(
                                r'^(?=.*[a-z])(?=.*\d)(?=.*[A-Z])(?=.*\W)([a-zA-Z\d\W]{8,64})$',
                                string=tmp_pass
                            ):
                namespace.password = tmp_pass
            else:
                raise ValueError(r"Password is too weak")

        return self

def age_it(string: str, password: str) -> bytes:
    """
    Encrypt input string with password
    require: password for actual encryption
    """
    if string and password:
        return passphrase.encrypt(string, password)

    return bytes()

def find_path(path_segment: str) -> Path:
    """
    Look for specified path in Linux PATH env variable
    """
    os_path = os.environ.get('PATH').split(':')
    for i in os_path:
        if path_segment in i:
            for element in list(Path(i).parents):
                if str(element).endswith(path_segment):
                    return Path(element)
    return None

def get_file_path(path: str) -> Path:
    """
    Handle wether the path is specidied by the user.
    Otherwise try to find existing path. 
    """
    if path:
        p_path = Path(path)
        if p_path.exists():
            return p_path

    return Path(find_path("AppData/Local"), 'Palo Alto Networks/GlobalProtect/PanGPA.log')


def get_last_hip(path: None, compres: bool) -> bytes:
    """
    Reads and parses PanGP.log and returns last send hip-report
    If path is provided reads the log from the path provided
    """
    ppath = get_file_path(path)

    if ppath.exists():
        with ppath.open(mode='r+', encoding="UTF-8") as file_descriptor:
            string_result = file_descriptor.read()
    regex_get = re.compile(r'(?ms)<hip-report\s.*?</hip-report>')
    fnd = regex_get.findall(string_result)[-1]

    if compres:
        return compress_it(bytes(fnd, encoding='UTF-8'), level=compres)
    return bytes(fnd, encoding='UTF-8')

def compress_it(obj: bytes, level: int) -> bytes:
    """
    zlib compression
    """
    return zlib.compress(obj, level=level)

if __name__ == "__main__":

    argP = ArgumentParser()
    argP.add_argument(
        '--password', '-p', help='Provide a password for file encryption',
        action=GetPass, nargs=0
    )
    argP.add_argument(
        '--output', '-o',
        help='Specify an output file where you want output data to be stored.',
        required=False
    )
    argP.add_argument(
        '--compress', '-c',
        help='''Compress the output with provided level of compression: 1 to 9. 
        Where 9 is the maximum compression and 1 is the least compression. 
        To decompress in linux use the following command:\n 
        printf "\\x1f\\x8b\\x08\\x00\\x00\\x00\\x00\\x00" |cat - <comressed_data_file> | gzip -dc
        ''',
        type=int,
        required=False
    )
    argP.add_argument(
        '--encode', '-e', action='store_true',
        help='Base64 encode the output', required=False
    )

    argP.add_argument(
        '--file', '-f',
        help='''
Provide the full path to PanGPA.log file.
Default set to /mnt/c/<USER>/AppData/Local/Palo Alto Networks/GlobalProtect/PanGPA.log\n
This is the case when you're on Windows and using WSL to run the script on. It does not support Windows directly.
''',
        required=False
    )

    a = argP.parse_args()

    if a.output:
        with open( file=a.output, mode='w+', encoding='UTF-8') as fd:
            if a.encode and a.password:
                fd.buffer.write(b64encode(age_it(get_last_hip(a.file, a.compress), a.password)))
            elif a.encode:
                fd.buffer.write(b64encode(get_last_hip(a.file, a.compress)))
            elif a.password:
                fd.buffer.write(age_it(get_last_hip(a.file, a.compress), a.password))
            else:
                fd.buffer.write(get_last_hip(a.file, a.compress))
    elif a.encode and a.password:
        sys.stdout.buffer.write(b64encode(age_it(get_last_hip(a.file, a.compress), a.password)))
    elif a.password:
        sys.stdout.buffer.write(age_it(get_last_hip(a.file, a.compress), a.password))
    elif a.encode:
        sys.stdout.buffer.write(b64encode(get_last_hip(a.file, a.compress)))
    else:
        sys.stdout.buffer.write(get_last_hip(a.file, a.compress))
