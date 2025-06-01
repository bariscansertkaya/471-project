from scapy.all import Ether, IP, UDP, Raw, sendp, get_if_hwaddr, get_if_addr
import random
import uuid
from crypto_utils import load_keys, import_public_key_base64, export_public_key_base64
from message import ChatMessage


# --- Settings ---
INTERFACE = "en0"  # Change this to your active network interface
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
DEST_IP = "255.255.255.255"
DEST_PORT = 42069  # Arbitrary UDP port


# --- MAC/IP Spoofing ---
def generate_fake_mac():
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0x00, 0xFF) for _ in range(5))

def generate_fake_ip():
    return "{}.{}.{}.{}".format(*[random.randint(1, 254) for _ in range(4)])


# --- Packet Sender ---
def send_encrypted_message(msg: ChatMessage, recipient_pubkey_b64: str):
    try:
        encrypted_bytes = msg.encrypt(import_public_key_base64(recipient_pubkey_b64))
    except Exception as e:
        print("[!] Encryption failed:", e)
        return

    # Wrap in Raw layer
    payload = Raw(load=encrypted_bytes)

    # Create spoofed Ethernet/IP/UDP packet
    pkt = Ether(src=generate_fake_mac(), dst=BROADCAST_MAC) / \
          IP(src=generate_fake_ip(), dst=DEST_IP) / \
          UDP(sport=random.randint(1024, 65535), dport=DEST_PORT) / \
          payload

    print(f"[*] Sending spoofed message from {pkt[IP].src} / {pkt[Ether].src}")
    sendp(pkt, iface=INTERFACE, verbose=False)


# --- Example Usage ---
if __name__ == "__main__":
    # Load keys
    priv, pub = load_keys()

    # Example public key to simulate broadcast (normally you'd use others' keys)
    pub_b64 = export_public_key_base64(pub)

    # Create sample message
    msg = ChatMessage("chat", "xxBarisxx", "Nabıyonuz!")
    send_encrypted_message(msg, pub_b64)
