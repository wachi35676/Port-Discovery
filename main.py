import tkinter as tk
from tkinter import ttk
import sys
from scapy.all import *
from scapy.layers.inet import TCP, ICMP, IP, UDP


class PortScannerGUI(tk.Tk):
    """
    A GUI application for port scanning using various techniques.

    This class inherits from the Tk class of tkinter module, which means it represents a main window.

    Attributes:
        target_ip_entry (ttk.Entry): An entry widget for inputting the target IP address.
        port_entry (ttk.Entry): An entry widget for inputting the port number.
        scan_type_var (tk.StringVar): A string variable for storing the selected scan type.
        scan_type_dropdown (ttk.Combobox): A dropdown menu for selecting the scan type.
        result_text (tk.Text): A text widget for displaying the scan results.
    """

    def __init__(self):
        """
        The constructor for PortScannerGUI class.

        It initializes the main window and all the widgets.
        """
        super().__init__()
        self.title("Port Discovery Techniques")
        self.geometry("500x400")

        # Create a frame for the target IP and port input
        input_frame = ttk.Frame(self)
        input_frame.pack(pady=10)

        ttk.Label(input_frame, text="Target IP:").grid(row=0, column=0, padx=5, pady=5)
        self.target_ip_entry = ttk.Entry(input_frame)
        self.target_ip_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(input_frame, text="Port:").grid(row=1, column=0, padx=5, pady=5)
        self.port_entry = ttk.Entry(input_frame)
        self.port_entry.grid(row=1, column=1, padx=5, pady=5)

        # Create a frame for the scan type selection
        scan_frame = ttk.Frame(self)
        scan_frame.pack(pady=10)

        ttk.Label(scan_frame, text="Select Scan Type:").pack(pady=5)
        self.scan_type_var = tk.StringVar()
        scan_types = ["ICMP Ping Scan", "UDP Ping Scan", "TCP SYN Scan", "TCP Stealth Scan", "TCP FIN Scan",
                      "TCP Null Scan", "TCP XMAS Scan", "TCP Maimon Scan", "TCP ACK Flag Scan",
                      "TCP TTL Based Scan", "TCP Window Scan"]
        self.scan_type_dropdown = ttk.Combobox(scan_frame, textvariable=self.scan_type_var, values=scan_types,
                                               state="readonly")
        self.scan_type_dropdown.pack(pady=5)

        # Create a button to run the scan
        run_button = ttk.Button(self, text="Run Scan", command=self.run_scan)
        run_button.pack(pady=10)

        # Create a text area to display the scan results
        self.result_text = tk.Text(self, height=10, width=50)
        self.result_text.pack(pady=10)

    def run_scan(self):
        """
        The function to run the selected scan.

        It retrieves the target IP, port, and scan type from the input widgets, clears the result text area,
        and calls the appropriate scan function based on the selected scan type.
        """
        target_ip = self.target_ip_entry.get()
        port = int(self.port_entry.get())
        scan_type = self.scan_type_var.get()

        # Clear the result text area
        self.result_text.delete("1.0", tk.END)

        # Call the appropriate scan function based on the selected scan type
        if scan_type == "ICMP Ping Scan":
            self.run_icmp_ping_scan(target_ip)
        elif scan_type == "UDP Ping Scan":
            self.run_udp_ping_scan(target_ip, port)
        elif scan_type == "TCP SYN Scan":
            self.run_tcp_syn_scan(target_ip, port)
        elif scan_type == "TCP Stealth Scan":
            self.run_tcp_stealth_scan(target_ip, port)
        elif scan_type == "TCP FIN Scan":
            self.run_tcp_fin_scan(target_ip, port)
        elif scan_type == "TCP Null Scan":
            self.run_tcp_null_scan(target_ip, port)
        elif scan_type == "TCP XMAS Scan":
            self.run_tcp_xmas_scan(target_ip, port)
        elif scan_type == "TCP Maimon Scan":
            self.run_tcp_maimon_scan(target_ip, port)
        elif scan_type == "TCP ACK Flag Scan":
            self.run_tcp_ack_scan(target_ip, port)
        elif scan_type == "TCP TTL Based Scan":
            self.run_tcp_ttl_scan(target_ip, port)
        elif scan_type == "TCP Window Scan":
            self.run_tcp_window_scan(target_ip, port)

    def run_icmp_ping_scan(self, target):
        """
        The function to run an ICMP ping scan.

        It sends an ICMP echo request to the target IP and checks if a reply is received.

        Args:
            target (str): The target IP address.
        """
        try:
            packets = IP(dst=target) / ICMP()
            replies = sr1(packets, timeout=2, verbose=0)
            if replies is not None:
                self.result_text.insert(tk.END, f"{target} is online\n")
            else:
                self.result_text.insert(tk.END, f"{target} is offline\n")
        except Exception as e:
            self.result_text.insert(tk.END, f"Error: {e}\n")

    def run_udp_ping_scan(self, target, port):
        """
        The function to run a UDP ping scan.

        It sends a UDP packet to the target IP and port and checks if a reply is received.

        Args:
            target (str): The target IP address.
            port (int): The port number.
        """
        try:
            packets = IP(dst=target) / UDP(dport=port)
            replies = sr1(packets, timeout=2, verbose=0)
            if replies is not None:
                self.result_text.insert(tk.END, f"{target}:{port} is open\n")
            else:
                self.result_text.insert(tk.END, f"{target}:{port} is closed\n")
        except Exception as e:
            self.result_text.insert(tk.END, f"Error: {e}\n")

    def run_tcp_syn_scan(self, target, port):
        """
        The function to run a TCP SYN scan.

        It sends a TCP SYN packet to the target IP and port and checks the flags of the received reply.

        Args:
            target (str): The target IP address.
            port (int): The port number.
        """
        try:
            packets = IP(dst=target) / TCP(sport=RandShort(), dport=port, flags='S')
            replies = sr1(packets, timeout=2, verbose=0)
            if replies is not None and replies.haslayer(TCP):
                if replies.getlayer(TCP).flags == 0x12:
                    self.result_text.insert(tk.END, f"{target}:{port} is open\n")
                elif replies.getlayer(TCP).flags == 0x14:
                    self.result_text.insert(tk.END, f"{target}:{port} is closed\n")
        except Exception as e:
            self.result_text.insert(tk.END, f"Error: {e}\n")

    def run_tcp_stealth_scan(self, target, port):
        """
        The function to run a TCP stealth scan.

        It sends a TCP SYN packet to the target IP and port, checks the flags of the received reply,
        and if the SYN-ACK flag is set, it sends a RST packet to close the connection.

        Args:
            target (str): The target IP address.
            port (int): The port number.
        """
        try:
            packets = IP(dst=target) / TCP(sport=RandShort(), dport=port, flags='S')
            replies = sr1(packets, timeout=2, verbose=0)
            if replies is not None and replies.haslayer(TCP):
                if replies.getlayer(TCP).flags == 0x12:
                    rst_packet = IP(dst=target) / TCP(sport=RandShort(), dport=port, flags='R')
                    send(rst_packet, verbose=0)
                    self.result_text.insert(tk.END, f"{target}:{port} is open\n")
        except Exception as e:
            self.result_text.insert(tk.END, f"Error: {e}\n")

    def run_tcp_fin_scan(self, target, port):
        """
        The function to run a TCP FIN scan.

        It sends a TCP FIN packet to the target IP and port and checks the flags of the received reply.

        Args:
            target (str): The target IP address.
            port (int): The port number.
        """
        try:
            packets = IP(dst=target) / TCP(sport=RandShort(), dport=port, flags='F')
            replies = sr1(packets, timeout=2, verbose=0)
            if replies is not None and replies.haslayer(TCP):
                if replies.getlayer(TCP).flags == 0x14:
                    self.result_text.insert(tk.END, f"{target}:{port} is closed\n")
                else:
                    self.result_text.insert(tk.END, f"{target}:{port} is open or filtered\n")
        except Exception as e:
            self.result_text.insert(tk.END, f"Error: {e}\n")

    def run_tcp_null_scan(self, target, port):
        """
        The function to run a TCP null scan.

        It sends a TCP packet with no flags set to the target IP and port and checks the flags of the received reply.

        Args:
            target (str): The target IP address.
            port (int): The port number.
        """
        try:
            packets = IP(dst=target) / TCP(sport=RandShort(), dport=port, flags='')
            replies = sr1(packets, timeout=2, verbose=0)
            if replies is not None and replies.haslayer(TCP):
                if replies.getlayer(TCP).flags == 0x14:
                    self.result_text.insert(tk.END, f"{target}:{port} is closed\n")
                else:
                    self.result_text.insert(tk.END, f"{target}:{port} is open or filtered\n")
        except Exception as e:
            self.result_text.insert(tk.END, f"Error: {e}\n")

    def run_tcp_xmas_scan(self, target, port):
        """
        The function to run a TCP XMAS scan.

        It sends a TCP packet with FIN, PSH, and URG flags set to the target IP and port and checks the flags of the received reply.

        Args:
            target (str): The target IP address.
            port (int): The port number.
        """
        try:
            packets = IP(dst=target) / TCP(sport=RandShort(), dport=port, flags='FPU')
            replies = sr1(packets, timeout=2, verbose=0)
            if replies is not None and replies.haslayer(TCP):
                if replies.getlayer(TCP).flags == 0x14:
                    self.result_text.insert(tk.END, f"{target}:{port} is closed\n")
                else:
                    self.result_text.insert(tk.END, f"{target}:{port} is open or filtered\n")
        except Exception as e:
            self.result_text.insert(tk.END, f"Error: {e}\n")

    def run_tcp_maimon_scan(self, target, port):
        """
        The function to run a TCP Maimon scan.

        It sends a TCP packet with FIN and PSH flags set to the target IP and port and checks the flags of the received reply.

        Args:
            target (str): The target IP address.
            port (int): The port number.
        """
        try:
            packets = IP(dst=target) / TCP(sport=RandShort(), dport=port, flags='FPU')
            replies = sr1(packets, timeout=2, verbose=0)
            if replies is not None and replies.haslayer(TCP):
                if replies.getlayer(TCP).flags == 0x14:
                    self.result_text.insert(tk.END, f"{target}:{port} is closed\n")
                else:
                    self.result_text.insert(tk.END, f"{target}:{port} is open or filtered\n")
        except Exception as e:
            self.result_text.insert(tk.END, f"Error: {e}\n")

    def run_tcp_ack_scan(self, target, port):
        """
        The function to run a TCP ACK scan.

        It sends a TCP ACK packet to the target IP and port and checks the flags of the received reply.

        Args:
            target (str): The target IP address.
            port (int): The port number.
        """
        try:
            packets = IP(dst=target) / TCP(sport=RandShort(), dport=port, flags='A')
            replies = sr1(packets, timeout=2, verbose=0)
            if replies is not None and replies.haslayer(TCP):
                if replies.getlayer(TCP).flags == 0x4:
                    self.result_text.insert(tk.END, f"{target}:{port} is unfiltered\n")
                else:
                    self.result_text.insert(tk.END, f"{target}:{port} is filtered\n")
        except Exception as e:
            self.result_text.insert(tk.END, f"Error: {e}\n")

    def run_tcp_ttl_scan(self, target, port):
        """
        The function to run a TCP TTL based scan.

        It sends a TCP SYN packet with a TTL of 20 to the target IP and port and checks the type and code of the received ICMP reply.

        Args:
            target (str): The target IP address.
            port (int): The port number.
        """
        try:
            packets = IP(dst=target, ttl=20) / TCP(sport=RandShort(), dport=port, flags='S')
            replies = sr1(packets, timeout=2, verbose=0)
            if replies is not None and replies.haslayer(ICMP):
                if int(replies.getlayer(ICMP).code) == 3 and int(replies.getlayer(ICMP).type) == 3:
                    self.result_text.insert(tk.END, f"{target}:{port} is closed\n")
                else:
                    self.result_text.insert(tk.END, f"{target}:{port} is open or filtered\n")
        except Exception as e:
            self.result_text.insert(tk.END, f"Error: {e}\n")

    def run_tcp_window_scan(self, target, port):
        """
        The function to run a TCP window scan.

        It sends a TCP ACK packet to the target IP and port and checks the window size of the received reply.

        Args:
            target (str): The target IP address.
            port (int): The port number.
        """
        try:
            packets = IP(dst=target) / TCP(sport=RandShort(), dport=port, flags='A')
            replies = sr1(packets, timeout=2, verbose=0)
            if replies is not None and replies.haslayer(TCP):
                if replies.getlayer(TCP).window == 0:
                    self.result_text.insert(tk.END, f"{target}:{port} is closed\n")
                else:
                    self.result_text.insert(tk.END, f"{target}:{port} is open or filtered\n")
        except Exception as e:
            self.result_text.insert(tk.END, f"Error: {e}\n")


if __name__ == "__main__":
    """
    The main entry point of the application.
    """
    app = PortScannerGUI()
    app.mainloop()
