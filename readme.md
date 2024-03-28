# Port Discovery Techniques

This is a Python GUI application for performing various port scanning techniques using the Scapy library. The application allows you to scan a target IP address for open ports using different scanning methods.

## Features

- ICMP Ping Scan: Checks if the target IP address is online or offline using ICMP echo requests.
- UDP Ping Scan: Checks if a specific port on the target IP address is open or closed using UDP packets.
- TCP SYN Scan: Performs a TCP SYN scan to check if a specific port on the target IP address is open or closed.
- TCP Stealth Scan: Performs a TCP stealth scan by sending a SYN packet and closing the connection with a RST packet if the port is open.
- TCP FIN Scan: Sends a TCP FIN packet to check if a specific port on the target IP address is closed or open/filtered.
- TCP Null Scan: Sends a TCP packet with no flags set to check if a specific port on the target IP address is closed or open/filtered.
- TCP XMAS Scan: Sends a TCP packet with FIN, PSH, and URG flags set to check if a specific port on the target IP address is closed or open/filtered.
- TCP Maimon Scan: Sends a TCP packet with FIN and PSH flags set to check if a specific port on the target IP address is closed or open/filtered.
- TCP ACK Flag Scan: Sends a TCP ACK packet to check if a specific port on the target IP address is filtered or unfiltered.
- TCP TTL Based Scan: Sends a TCP SYN packet with a TTL of 20 and checks the ICMP reply to determine if a specific port on the target IP address is closed or open/filtered.
- TCP Window Scan: Sends a TCP ACK packet and checks the window size of the reply to determine if a specific port on the target IP address is closed or open/filtered.

## Requirements

- Python 3.x
- Scapy library (`pip install scapy`)
- tkinter library (usually included in Python standard library)

## Usage

1. Run the `main.py` script.
2. Enter the target IP address in the "Target IP" field.
3. Enter the port number in the "Port" field.
4. Select the desired scan type from the dropdown menu.
5. Click the "Run Scan" button to start the scan.
6. The scan results will be displayed in the text area below.

## Contributing

Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request.

## License

This project is licensed under the [MIT License](LICENSE).