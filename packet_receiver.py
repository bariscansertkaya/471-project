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
def handle_packet(self, packet):
    if not packet.haslayer(Raw):
        return

    raw_data = packet[Raw].load

    # 1. Önce şifre çözmeyi dener, eğer şifreli ise parse eder
    try:
        message = ChatMessage.decrypt(raw_data, self.private_key)
        if message:
            self.message_received.emit(message.nickname, message.type, message.data)
        return
    except Exception as e:
        pass

    # 2. Eğer şifreli değilse, raw mesajını parse eder
    try:
        message = ChatMessage.from_bytes(raw_data)
        if message:
            self.message_received.emit(message.nickname, message.type, message.data)
    except Exception as e:
        print(f"[!] Failed to parse raw message: {e}")



# --- Main Sniffer ---
def start_sniffing():
    print(f"[*] Listening for chat messages on interface '{INTERFACE}'...")
    sniff(iface=INTERFACE, prn=handle_packet, filter=f"udp port {DEST_PORT}", store=False)


# --- Entry Point ---
if __name__ == "__main__":
    private_key, _ = load_keys()
    start_sniffing()
