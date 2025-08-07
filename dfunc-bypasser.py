#!/usr/bin/env python3
import argparse
import requests

class colors:
    reset = '\033[0m'
    red = '\033[31m'
    green = '\033[32m'
    orange = '\033[33m'
    blue = '\033[34m'

print(colors.green + """
                                ,---,     
                                  .'  .' `\\   
                                  ,---.'     \\  
                                  |   |  .`\\  | 
                                  :   : |  '  | 
                                  |   ' '  ;  : 
                                  '   | ;  .  | 
                                  |   | :  |  ' 
                                  '   : | /  ;  
                                  |   | '` ,/   
                                  ;   :  .'     
                                  |   ,.'       
                                  '---'         
""" + "\n\t\t\t" + colors.blue + "authors: " + colors.orange + "__c3rb3ru5__" + ", " + "$_SpyD3r_$" + "\n" + colors.reset)

parser = argparse.ArgumentParser()
parser.add_argument("--url", help="PHPinfo URL: eg. https://example.com/phpinfo.php")
parser.add_argument("--file", help="PHPinfo localfile path: eg. dir/phpinfo")
parser.add_argument("--header", action="append", help="Custom headers, format: 'Header-Name: value'")

args = parser.parse_args()

# Parsowanie custom headers
headers = {}
if args.header:
    for h in args.header:
        if ':' in h:
            key, value = h.split(':', 1)
            headers[key.strip()] = value.strip()

if args.url:
    try:
        phpinfo = requests.get(args.url, headers=headers, verify=False, timeout=10).text
    except Exception as e:
        print(colors.red + f"[!] Error during download file: {e}" + colors.reset)
        exit()
elif args.file:
    try:
        with open(args.file, 'r') as f:
            phpinfo = f.read()
    except Exception as e:
        print(colors.red + f"[!] Error during read the file: {e}" + colors.reset)
        exit()
else:
    parser.print_help()
    exit()

modules = []
inp = []

try:
    inp = phpinfo.split('disable_functions</td><td class="v">')[1].split("</")[0].split(',')
except IndexError:
    print(colors.red + "[!] Nothing disable_functions in phpinfo." + colors.reset)
    exit()

dangerous_functions = [
    'pcntl_alarm', 'pcntl_fork', 'pcntl_waitpid', 'pcntl_wait', 'pcntl_wifexited', 'pcntl_wifstopped',
    'pcntl_wifsignaled', 'pcntl_wifcontinued', 'pcntl_wexitstatus', 'pcntl_wtermsig', 'pcntl_wstopsig',
    'pcntl_signal', 'pcntl_signal_get_handler', 'pcntl_signal_dispatch', 'pcntl_get_last_error',
    'pcntl_strerror', 'pcntl_sigprocmask', 'pcntl_sigwaitinfo', 'pcntl_sigtimedwait', 'pcntl_exec',
    'pcntl_getpriority', 'pcntl_setpriority', 'pcntl_async_signals', 'error_log', 'system', 'exec',
    'shell_exec', 'popen', 'proc_open', 'passthru', 'link', 'symlink', 'syslog', 'ld', 'mail'
]

# Recognize existing modules
if "mbstring.ini" in phpinfo:
    modules.append('mbstring')
    dangerous_functions += ['mb_send_mail']

if "imap.ini" in phpinfo:
    modules.append('imap')
    dangerous_functions += ['imap_open', 'imap_mail']

if "libvirt-php.ini" in phpinfo:
    modules.append('libvert')
    dangerous_functions += ['libvirt_connect']

if "gnupg.ini" in phpinfo:
    modules.append('gnupg')
    dangerous_functions += ['gnupg_init']

if "imagick.ini" in phpinfo:
    modules.append('imagick')

exploitable_functions = []

for func in dangerous_functions:
    if func not in inp:
        exploitable_functions.append(func)

# Results
if len(exploitable_functions) == 0:
    print(colors.green + '\n[+] All dangerous functions was disabled.' + colors.reset)
else:
    print(colors.orange + '\n[-] Potential dangerous functions (not disabled):' + colors.reset)
    print(', '.join(exploitable_functions))

if "imagick" in modules:
    print(colors.blue + '\n[!] Module imagick is exist — possible exploit via LD_PRELOAD.\n' + colors.reset)

if "PHP-FPM" in phpinfo:
    print(colors.blue + "[!] Possible to exploit via stream_socket_sendto/fsockopen z PHP-FPM.\n" + colors.reset)
