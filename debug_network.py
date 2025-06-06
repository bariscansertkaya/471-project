#!/usr/bin/env python3
"""
Network debugging script for gateway setup
"""

import socket
import subprocess
import sys
import os
from scapy.all import get_if_list, get_if_addr, get_if_hwaddr


def get_local_ip():
    """Get the local IP address"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        return local_ip
    except:
        return "Unable to determine"


def list_network_interfaces():
    """List all network interfaces"""
    print("=== Network Interfaces ===")
    try:
        interfaces = get_if_list()
        for iface in interfaces:
            try:
                ip = get_if_addr(iface)
                mac = get_if_hwaddr(iface)
                print(f"Interface: {iface}")
                print(f"  IP: {ip}")
                print(f"  MAC: {mac}")
                print()
            except:
                print(f"Interface: {iface} (no IP assigned)")
                print()
    except Exception as e:
        print(f"Error listing interfaces: {e}")


def test_gateway_port(target_ip):
    """Test if gateway port is reachable"""
    print(f"=== Testing Gateway Port on {target_ip} ===")
    port = 42070
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((target_ip, port))
        sock.close()
        
        if result == 0:
            print(f"✅ Port {port} is OPEN on {target_ip}")
            return True
        else:
            print(f"❌ Port {port} is CLOSED on {target_ip}")
            return False
    except Exception as e:
        print(f"❌ Error testing port: {e}")
        return False


def check_gateways_file():
    """Check gateways.txt configuration"""
    print("=== Gateway Configuration ===")
    
    if not os.path.exists("gateways.txt"):
        print("❌ gateways.txt file not found!")
        print("Create it with remote gateway IP addresses")
        return False
    
    with open("gateways.txt", "r") as f:
        lines = f.readlines()
    
    gateway_ips = []
    for line in lines:
        line = line.strip()
        if line and not line.startswith('#'):
            gateway_ips.append(line)
    
    if not gateway_ips:
        print("❌ No gateway IPs found in gateways.txt")
        return False
    
    print(f"✅ Found {len(gateway_ips)} gateway(s):")
    for ip in gateway_ips:
        print(f"  - {ip}")
    
    return gateway_ips


def check_packet_sender_interface():
    """Check packet_sender.py interface configuration"""
    print("=== Packet Sender Interface ===")
    
    try:
        with open("packet_sender.py", "r") as f:
            content = f.read()
        
        # Find INTERFACE line
        for line in content.split('\n'):
            if 'INTERFACE = ' in line and not line.strip().startswith('#'):
                print(f"Current setting: {line.strip()}")
                # Extract interface name
                interface = line.split('"')[1] if '"' in line else line.split("'")[1]
                
                # Check if this interface exists
                try:
                    ip = get_if_addr(interface)
                    print(f"✅ Interface {interface} exists with IP: {ip}")
                    return True
                except:
                    print(f"❌ Interface {interface} not found or has no IP!")
                    print("Available interfaces:")
                    for iface in get_if_list():
                        try:
                            iface_ip = get_if_addr(iface)
                            if iface_ip != "0.0.0.0":
                                print(f"  - {iface} ({iface_ip})")
                        except:
                            pass
                    return False
                    
    except Exception as e:
        print(f"❌ Error checking packet_sender.py: {e}")
        return False


def run_ping_test(target_ip):
    """Test basic connectivity with ping"""
    print(f"=== Ping Test to {target_ip} ===")
    
    try:
        # Use ping command
        if sys.platform.startswith('win'):
            cmd = ['ping', '-n', '3', target_ip]
        else:
            cmd = ['ping', '-c', '3', target_ip]
            
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            print(f"✅ Ping to {target_ip} successful")
            return True
        else:
            print(f"❌ Ping to {target_ip} failed")
            print(f"Error: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"❌ Ping test error: {e}")
        return False


def main():
    print("🔍 Gateway Network Debugging Tool")
    print("=" * 50)
    
    # Basic network info
    local_ip = get_local_ip()
    print(f"Detected local IP: {local_ip}")
    print()
    
    # List interfaces
    list_network_interfaces()
    
    # Check packet sender interface
    check_packet_sender_interface()
    print()
    
    # Check gateway configuration
    gateway_ips = check_gateways_file()
    print()
    
    if gateway_ips:
        # Test connectivity to each gateway
        for gateway_ip in gateway_ips:
            run_ping_test(gateway_ip)
            test_gateway_port(gateway_ip)
            print()
    
    print("=" * 50)
    print("🛠️  Common Issues and Solutions:")
    print()
    print("1. **Interface not found**: Update INTERFACE in packet_sender.py")
    print("2. **Port closed**: Check firewall, ensure gateway mode is active")
    print("3. **Ping fails**: Check network connectivity, VM bridge mode")
    print("4. **No gateways**: Add remote IPs to gateways.txt")
    print()
    print("📚 See GATEWAY_SETUP_GUIDE.md for detailed instructions")


if __name__ == "__main__":
    main() 