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

# --- Encrypted Message Sender ---
def send_encrypted_message(msg: ChatMessage, recipient_pubkey_b64: str):
    print("[debug] recipient_pubkey_b64 length:", len(recipient_pubkey_b64))
    try:
        encrypted_bytes = msg.encrypt(import_public_key_base64(recipient_pubkey_b64))
    except Exception as e:
        print("[!] Encryption failed:", e)
        return

    payload = Raw(load=encrypted_bytes)
    pkt = Ether(src=generate_fake_mac(), dst=BROADCAST_MAC) / \
          IP(src=generate_fake_ip(), dst=DEST_IP) / \
          UDP(sport=random.randint(1024, 65535), dport=DEST_PORT) / \
          payload

    print(f"[*] Sending spoofed encrypted message from {pkt[IP].src} / {pkt[Ether].src}")
    sendp(pkt, iface=INTERFACE, verbose=False)

# --- Unencrypted Raw Message Sender ---
def send_raw_message(msg: ChatMessage):
    try:
        raw_bytes = msg.to_bytes()
    except Exception as e:
        print("[!] Failed to serialize message:", e)
        return

    payload = Raw(load=raw_bytes)
    pkt = Ether(src=generate_fake_mac(), dst=BROADCAST_MAC) / \
          IP(src=generate_fake_ip(), dst=DEST_IP) / \
          UDP(sport=random.randint(1024, 65535), dport=DEST_PORT) / \
          payload

    print(f"[*] Sending RAW message {msg.type} from {pkt[IP].src} / {pkt[Ether].src}")
    sendp(pkt, iface=INTERFACE, verbose=False)

# --- Example Usage ---
if __name__ == "__main__":
    priv, pub = load_keys()
    pub_b64 = export_public_key_base64(pub)

    msg = ChatMessage("join", "xxBarisxx", pub_b64)
    send_raw_message(msg)
