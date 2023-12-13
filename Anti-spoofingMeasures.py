import socket
import struct

class AntiSpoofing:
    def __init__(self, interface):
        self.interface = interface

    def get_mac_address(self):
        # Get the MAC address of the interface
        with open('/sys/class/net/{}/address'.format(self.interface), 'r') as f:
            mac_address = f.read().strip()
        return mac_address

    def get_ip_address(self):
        # Get the IP address of the interface
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 1))
        ip_address = s.getsockname()[0]
        s.close()
        return ip_address

    def validate_packet(self, packet):
        # Extract the source MAC address and IP address from the packet
        ethernet_header = packet[:14]
        ethernet_header_values = struct.unpack('!6s6sH', ethernet_header)
        source_mac = ':'.join('%02x' % b for b in ethernet_header_values[1])
        ip_header = packet[14:34]
        ip_header_values = struct.unpack('!BBHHHBBH4s4s', ip_header)
        source_ip = socket.inet_ntoa(ip_header_values[8])

        # Compare the source MAC address and IP address with the interface's MAC address and IP address
        if source_mac != self.get_mac_address() or source_ip != self.get_ip_address():
            print("Spoofed packet detected!")
        else:
            print("Packet is valid.")

if __name__ == "__main__":
    # Instantiate the AntiSpoofing class with the interface name
    anti_spoofing = AntiSpoofing('eth0')

    # Simulate a packet with a spoofed MAC address and IP address
    packet = b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00\x45\x00\x00\x28\x00\x01\x00\x00\x40\x11\x7c\x4c\xc0\xa8\x01\x01\xc0\xa8\x01\x02\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

    # Validate the packet
    anti_spoofing.validate_packet(packet)
