from scapy.all import sniff, Raw
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from crypto_utils import load_keys
from message import ChatMessage
from peer_manager import PeerManager
import base64

# --- Settings ---
INTERFACE = "en0"  # Change to your network interface
DEST_PORT = 42069  # Must match sender

# --- Message Handler ---
def handle_packet(packet):
    if not packet.haslayer(Raw):
        return

    raw_data = packet[Raw].load

    try:
        # Attempt to decrypt the message
        message = ChatMessage.decrypt(raw_data, private_key)
        if message:
            print(f"\n📩 Received message from {message.nickname} [{message.type}] @ {message.timestamp}")
            print(f"   ➤ {message.data}")
        else:
            print("[!] Failed to parse ChatMessage.")

    except Exception as e:
        print(f"[!] Error processing packet: {e}")


# --- Main Sniffer ---
def start_sniffing():
    print(f"[*] Listening for chat messages on interface '{INTERFACE}'...")
    sniff(iface=INTERFACE, prn=handle_packet, filter=f"udp port {DEST_PORT}", store=False)


# --- Entry Point ---
if __name__ == "__main__":
    private_key, _ = load_keys()
    start_sniffing()
