import sys
from scapy.all import *
from scapy.layers.inet import TCP, ICMP, IP, UDP


# Clear the terminal screen
def clear_screen():
    if sys.platform.startswith('win'):
        os.system('cls')
    else:
        os.system('clear')


# ICMP Ping Scan
def icmp_ping_scan(target):
    try:
        packets = IP(dst=target) / ICMP()
        replies = sr1(packets, timeout=2, verbose=0)
        if replies is not None:
            print(f"{target} is online")
        else:
            print(f"{target} is offline")
    except Exception as e:
        print(f"Error: {e}")


# UDP Ping Scan
def udp_ping_scan(target, port):
    try:
        packets = IP(dst=target) / UDP(dport=port)
        replies = sr1(packets, timeout=2, verbose=0)
        if replies is not None:
            print(f"{target}:{port} is open")
        else:
            print(f"{target}:{port} is closed")
    except Exception as e:
        print(f"Error: {e}")


# TCP SYN Scan (Full Open Scan)
def tcp_syn_scan(target, port):
    try:
        packets = IP(dst=target) / TCP(sport=RandShort(), dport=port, flags='S')
        replies = sr1(packets, timeout=2, verbose=0)
        if replies is not None and replies.haslayer(TCP):
            if replies.getlayer(TCP).flags == 0x12:
                print(f"{target}:{port} is open")
            elif replies.getlayer(TCP).flags == 0x14:
                print(f"{target}:{port} is closed")
    except Exception as e:
        print(f"Error: {e}")


# TCP Stealth Scan (Half Open Scan)
def tcp_stealth_scan(target, port):
    try:
        packets = IP(dst=target) / TCP(sport=RandShort(), dport=port, flags='S')
        replies = sr1(packets, timeout=2, verbose=0)
        if replies is not None and replies.haslayer(TCP):
            if replies.getlayer(TCP).flags == 0x12:
                rst_packet = IP(dst=target) / TCP(sport=RandShort(), dport=port, flags='R')
                send(rst_packet, verbose=0)
                print(f"{target}:{port} is open")
    except Exception as e:
        print(f"Error: {e}")


# TCP FIN Scan
def tcp_fin_scan(target, port):
    try:
        packets = IP(dst=target) / TCP(sport=RandShort(), dport=port, flags='F')
        replies = sr1(packets, timeout=2, verbose=0)
        if replies is not None and replies.haslayer(TCP):
            if replies.getlayer(TCP).flags == 0x14:
                print(f"{target}:{port} is closed")
            else:
                print(f"{target}:{port} is open or filtered")
    except Exception as e:
        print(f"Error: {e}")


# TCP Null Scan
def tcp_null_scan(target, port):
    try:
        packets = IP(dst=target) / TCP(sport=RandShort(), dport=port, flags='')
        replies = sr1(packets, timeout=2, verbose=0)
        if replies is not None and replies.haslayer(TCP):
            if replies.getlayer(TCP).flags == 0x14:
                print(f"{target}:{port} is closed")
            else:
                print(f"{target}:{port} is open or filtered")
    except Exception as e:
        print(f"Error: {e}")


# TCP XMAS Scan (Does not work on Windows)
def tcp_xmas_scan(target, port):
    try:
        packets = IP(dst=target) / TCP(sport=RandShort(), dport=port, flags='FPU')
        replies = sr1(packets, timeout=2, verbose=0)
        if replies is not None and replies.haslayer(TCP):
            if replies.getlayer(TCP).flags == 0x14:
                print(f"{target}:{port} is closed")
            else:
                print(f"{target}:{port} is open or filtered")
    except Exception as e:
        print(f"Error: {e}")


# TCP Maimon Scan (Does not work on Windows)
def tcp_maimon_scan(target, port):
    try:
        packets = IP(dst=target) / TCP(sport=RandShort(), dport=port, flags='FPU')
        replies = sr1(packets, timeout=2, verbose=0)
        if replies is not None and replies.haslayer(TCP):
            if replies.getlayer(TCP).flags == 0x14:
                print(f"{target}:{port} is closed")
            else:
                print(f"{target}:{port} is open or filtered")
    except Exception as e:
        print(f"Error: {e}")


# TCP ACK Flag Scan
def tcp_ack_scan(target, port):
    try:
        packets = IP(dst=target) / TCP(sport=RandShort(), dport=port, flags='A')
        replies = sr1(packets, timeout=2, verbose=0)
        if replies is not None and replies.haslayer(TCP):
            if replies.getlayer(TCP).flags == 0x4:
                print(f"{target}:{port} is unfiltered")
            else:
                print(f"{target}:{port} is filtered")
    except Exception as e:
        print(f"Error: {e}")


# TCP TTL Based Scan
def tcp_ttl_scan(target, port):
    try:
        packets = IP(dst=target, ttl=20) / TCP(sport=RandShort(), dport=port, flags='S')
        replies = sr1(packets, timeout=2, verbose=0)
        if replies is not None and replies.haslayer(ICMP):
            if int(replies.getlayer(ICMP).code) == 3 and int(replies.getlayer(ICMP).type) == 3:
                print(f"{target}:{port} is closed")
            else:
                print(f"{target}:{port} is open or filtered")
    except Exception as e:
        print(f"Error: {e}")


# TCP Window Scan
def tcp_window_scan(target, port):
    try:
        packets = IP(dst=target) / TCP(sport=RandShort(), dport=port, flags='A')
        replies = sr1(packets, timeout=2, verbose=0)
        if replies is not None and replies.haslayer(TCP):
            if replies.getlayer(TCP).window == 0:
                print(f"{target}:{port} is closed")
            else:
                print(f"{target}:{port} is open or filtered")
    except Exception as e:
        print(f"Error: {e}")


def main():
    clear_screen()
    print("Port Discovery Techniques")
    print("1. ICMP Ping Scan")
    print("2. UDP Ping Scan")
    print("3. TCP Scan")
    print("   a. SYN Scan (Full Open Scan)")
    print("   b. Stealth Scan (Half Open Scan)")
    print("   c. Inverse TCP Flag Scan")
    print("      i.   FIN Scan")
    print("      ii.  Null Scan")
    print("      iii. XMAS Scan (Does not work on Windows)")
    print("      iv.  Maimon Scan (Does not work on Windows)")
    print("   d. ACK Flag Scan")
    print("      i.   TTL Based Scan")
    print("      ii.  Window Scan")

    choice = input("Enter your choice: ")
    target = input("Enter the target IP address: ")
    port = int(input("Enter the port number: "))

    if choice == "1":
        icmp_ping_scan(target)
    elif choice == "2":
        udp_ping_scan(target, port)
    elif choice == "3a":
        tcp_syn_scan(target, port)
    elif choice == "3b":
        tcp_stealth_scan(target, port)
    elif choice == "3ci":
        tcp_fin_scan(target, port)
    elif choice == "3cii":
        tcp_null_scan(target, port)
    elif choice == "3ciii":
        tcp_xmas_scan(target, port)
    elif choice == "3civ":
        tcp_maimon_scan(target, port)
    elif choice == "3di":
        tcp_ack_scan(target, port)
    elif choice == "3dii":
        tcp_ttl_scan(target, port)
    elif choice == "3diii":
        tcp_window_scan(target, port)
    else:
        print("Invalid choice")


if __name__ == '__main__':
    main()
