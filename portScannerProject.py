from scapy.all import ARP, Ether, IP, TCP, srp, sr1, ICMP
import ipaddress
import time  # Import the time module

def arp_scan(ip_range, delay=0.1):
    """Scans a local network for active hosts using ARP with a delay.

    Args:
        ip_range (str): The IP address range to scan (e.g., "192.168.1.0/24").
        delay (float): Time in seconds to wait between sending each ARP request.

    Returns:
        list: A list of IP addresses of active hosts.
    """
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_range)
    answered, unanswered = srp(arp_request, timeout=1, verbose=0)

    active_ips = []
    for sent, received in answered:
        active_ips.append(received.psrc)
        time.sleep(delay)  # Add a delay after processing each response
        #if len(active_ips) >= 10:  # Limit the number of active hosts to 10
        #    break  # Stop scanning once we have found 10 active hosts

    print(f"Active hosts in {ip_range}: {', '.join(map(str, active_ips))}") 
    return active_ips

def syn_scan(target_ip, ports, delay=0.05):
    """Performs a TCP SYN scan on a target host and list of ports with a delay.

    Args:
        target_ip (str): The IP address of the target host.
        ports (list): A list of port numbers to scan.
        delay (float): Time in seconds to wait between sending each SYN packet.

    Returns:
        list: A list of open ports.
    """
    open_ports = []
    for port in ports:
        syn_packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
        response = sr1(syn_packet, timeout=0.2, verbose=0)
        time.sleep(delay) # Add a delay after sending each SYN packet

        if response is not None:
            if isinstance(response, TCP): # Check if response is a TCP layer directly
                if response.flags == "SA":
                    open_ports.append(port)
                elif response.flags == "RA":
                    pass  # Port is closed
            elif isinstance(response, IP) and response.haslayer(ICMP):
                if response.getlayer(ICMP).type == 3 and response.getlayer(ICMP).code in [1, 2, 3, 9, 10, 13]:
                    print(f"[{target_ip}:{port}] Filtered (ICMP unreachable)")
        else:
            print(f"[{target_ip}:{port}] No response (Filtered or host down)")
    return open_ports

if __name__ == "__main__":
    target_network = "10.40.37.190/16"  # Replace with your network range
    ports_to_scan = [21, 22, 23, 80, 135, 443, 445, 3389, 8000] # Example ports
    arp_scan_delay = 0      # Delay in seconds for ARP scan
    syn_scan_delay = 0      # Delay in seconds for SYN scan

    print(f"Step 1: Scanning network {target_network} for active hosts using ARP...")
    active_hosts = arp_scan(target_network, delay=arp_scan_delay)

    if active_hosts:
        print("\nStep 2: Performing TCP SYN scan on active hosts...")
        results = {}
        for ip in active_hosts:
            print(f"\nScanning ports on {ip}...")
            open_ports = syn_scan(ip, ports_to_scan, delay=syn_scan_delay)
            if open_ports:
                print(f"Open ports on {ip}: {open_ports}")
                results[ip] = open_ports
            else:
                print(f"No open ports found on {ip} among the scanned ports.")
                results[ip] = [] # Indicate no open ports found

        print("\n--- Scan Results ---")
        if results:
            for ip, open_ports_list in results.items():
                print(f"IP: {ip}, Open Ports: {open_ports_list}")
        else:
            print("No active hosts found, so no port scan was performed.")
    else:
        print("No active hosts found on the network using ARP.")