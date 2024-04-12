



import socket  # Import the socket module for network communication
import struct  # Import the struct module for unpacking binary data
import textwrap  # Import the textwrap module for text formatting

def main():
    # Create a raw socket to capture Ethernet frames
    conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    while True:
        try:
            # Receive raw data and the address from the socket
            raw_data, addr = conn.recvfrom(65536)
            # Extract IP packet information
            src_ip, dest_ip, proto, data = ipv4_packet(raw_data)
            # Print IP packet details
            print('\nIPv4 Packet:')
            print('Source IP: {}, Destination IP: {}, Protocol: {}'.format(src_ip, dest_ip, proto))
        except KeyboardInterrupt:
            print("\nExiting...")
            break

    def ethernet_frame(data):
        # Unpack the Ethernet frame data
        dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
        # Return MAC addresses and protocol
        return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

    def get_mac_addr(bytes_addr):
        # Convert bytes to MAC address format (e.g., 'AA:BB:CC:DD:EE:FF')
        bytes_str = map('{:02x}'.format, bytes_addr)
        return ':'.join(bytes_str).upper()

    main()  # Call the main function to start the sniffer

