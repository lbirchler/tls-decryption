import argparse
import textwrap
import os
import subprocess
import sys
import tempfile
from pathlib import Path

def extract_pcap_randoms(pcap_file):
    """Extract client randoms from input capture file
    :pcap_file: input capture file 
    """
    cmd = f"tshark -r {pcap_file} -Y tls.handshake.type==1 -T fields -e tls.handshake.random"
    out = subprocess.getoutput(cmd)

    try:
        randoms = out.split('\n')
        randoms = [r for r in randoms if r != '']  # remove blank lines
    except AttributeError:
        pass

    if len(randoms[0]) == 64:  # client random will always be 64 chars long
        print(f"pcap client random count: {len(randoms)}")
        return randoms
    else:
        print(f"error extracting pcap client randoms: {randoms}")
        sys.exit(1)


def extract_keylog_randoms(key_log):
    """Extract client randoms from keylog file
    :key_log: path to read the keylog file for decryption

    Format: CLIENT RANDOM <Client Hello Random> <master secret>
    Example: CLIENT_RANDOM 5e85016c2010478311178455b55ee4c6cfd4fee8ef941b1a3fa07c3b3f86365c d6b14d253ebe0fb069185666afc8ca76216b1b288bc85b3c6e01a736e757f0ca4224693653d0e50ef5495f43e1910449
    """
    with open(key_log, "r") as f:
        content = f.readlines()

    randoms = []
    for random in content:
        if random.split()[0] == "CLIENT_RANDOM":
            randoms.append(random)

    print(f"keylog client random count: {len(randoms)}")

    return randoms


def filter_randoms(k_randoms, p_randoms):
    """Filter out any keys in the key log file that are not included in the capture file.
    :k_randoms: unique client randoms from key log
    :p_randoms: unique client randoms from capture file 
    """
    randoms = []
    for random in k_randoms:
        if random.split()[1] in p_randoms:
            randoms.append(random)

    diff = len(k_randoms) - len(randoms)

    print(f"client randoms removed from keylog file: {diff}")

    return randoms


def decrypt_tls_stream(key_file, pcap_file):
    """
    :key_log: path to read the TLS key log file for decryption
    :pcap_file: input capture file 
    """
    dsb_path = "dsb-" + Path(pcap_file).name

    cmd = f'editcap --discard-all-secrets --inject-secrets tls,{key_file} {pcap_file} {dsb_path}'
    out = subprocess.getoutput(cmd)

    print(out) if out else print(f"tls streams decrypted\ndecrypted pcap saved to: {dsb_path}\n")


def main(key_file, pcap_file):
    """
    :key_log: path to read the TLS key log file for decryption
    :pcap_file: input capture file (.pcap, .pcapng)
    """
    if not Path(pcap_file).exists():
        print(f"pcap file error: {pcap_file} doesn't exist")
        sys.exit(1)

    if not Path(key_file).exists():
        print(f"key log error: {key_file} doesn't exist")
        sys.exit(1)

    print("\n-- extracting client randoms --")
    p_randoms = extract_pcap_randoms(pcap_file)
    k_randoms = extract_keylog_randoms(key_file)
    client_randoms = filter_randoms(k_randoms, p_randoms)

    print("\n-- decrypting tls streams --")
    temp = tempfile.NamedTemporaryFile(mode="w+t")
    try:
        temp.writelines(''.join(client_randoms))
        temp.seek(0)
        decrypt_tls_stream(temp.name, pcap_file)
    finally:
        temp.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
            prog='decrypt.py',
            formatter_class=argparse.RawDescriptionHelpFormatter)
    required = parser.add_argument_group('required arguments')
    required.add_argument("-k", "--key_file", type=str,
            metavar="", help="key log file", required=True)
    required.add_argument("-p", "--pcap_file", type=str, metavar="",
            help="input capture file", required=True)

    if len(sys.argv) <= 1:
        parser.print_help()
        parser.exit()

    args = parser.parse_args()

    main(args.key_file, args.pcap_file)

