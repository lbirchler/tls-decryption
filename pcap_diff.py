import argparse
import subprocess
import sys
import textwrap
from pathlib import Path


def export_http_objects(pcap):
    """Extract http objects from packet capture
    :pcap: path of packet capture
    """
    cmd = f"tshark -r {pcap} --export-objects http,"
    out = subprocess.getoutput(cmd)
    return out.split("\n")


def extract_changed_packets(o_objs, d_objs):
    """Gather list of changed/altered packets
    :o_objs: list of packet objects from original pcap file
    :d_objs: list of packet objects from decrypted pcap file
    """
    changed = []
    for o, d in zip(o_objs, d_objs):
        if o != d:
            changed.append([o, d])
    return changed


def display_changed_packets(c_pkts):
    """
    :c_pkts: list of changed packets
    """
    for pkt in c_pkts:
        print(f"original:  {pkt[0]}\ndecrypted: {pkt[1]}\n")


def main(original_pcap, decrypted_pcap):

    if Path(original_pcap).exists() == False:
        print(f"original pcap file error: {original_pcap} doesn't exist")
        sys.exit(1)

    if Path(decrypted_pcap).exists() == False:
        print(f"decrypted pcap file error: {decrypted_pcap} doesn't exist")
        sys.exit(1)

    orig_pcap_objects = export_http_objects(original_pcap)
    dsb_pcap_objects = export_http_objects(decrypted_pcap)

    chg_packets = extract_changed_packets(orig_pcap_objects, dsb_pcap_objects)

    return chg_packets


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='pcap_diff.py', formatter_class=argparse.RawDescriptionHelpFormatter)
    required = parser.add_argument_group("required arguments")
    parser.add_argument("-p", "--print_diff", action="store_true",
                        help="display packets that were changed from original and decrypted pcap files")
    required.add_argument("-o", "--original", type=str,
                        metavar="", help="original pcap file")
    required.add_argument("-d", "--decrypted", type=str,
                        metavar="", help="decrypted pcap file")

    if len(sys.argv) <= 1:
        parser.print_help()
        parser.exit()

    args = parser.parse_args()

    diff = main(args.original, args.decrypted)

    if args.print_diff:
        display_changed_packets(diff)

    print(f"diff: {len(diff)}")
