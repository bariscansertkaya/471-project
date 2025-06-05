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
    print(f"[DEBUG] send_encrypted_message called:")
    print(f"  - Message type: {msg.type}")
    print(f"  - Sender: {msg.nickname}")
    print(f"  - Data length: {len(msg.data) if msg.data else 0}")
    print(f"  - Recipient pubkey length: {len(recipient_pubkey_b64) if recipient_pubkey_b64 else 0}")
    
    if not recipient_pubkey_b64:
        print("[ERROR] recipient_pubkey_b64 is None or empty!")
        return
    
    if len(recipient_pubkey_b64) < 100:  # RSA 2048 base64 should be much longer
        print(f"[ERROR] recipient_pubkey_b64 seems too short: {len(recipient_pubkey_b64)} chars")
        print(f"[ERROR] Content: {recipient_pubkey_b64[:100]}...")
        return
    
    try:
        print("[DEBUG] Attempting to import public key...")
        recipient_pubkey = import_public_key_base64(recipient_pubkey_b64)
        print("[DEBUG] Public key imported successfully")
        
        print("[DEBUG] Attempting to encrypt message...")
        encrypted_bytes = msg.encrypt(recipient_pubkey)
        print(f"[DEBUG] Message encrypted successfully, size: {len(encrypted_bytes)} bytes")
        
    except Exception as e:
        print(f"[ERROR] Encryption failed: {e}")
        import traceback
        traceback.print_exc()
        return

    try:
        payload = Raw(load=encrypted_bytes)
        fake_mac = generate_fake_mac()
        fake_ip = generate_fake_ip()
        
        pkt = Ether(src=fake_mac, dst=BROADCAST_MAC) / \
              IP(src=fake_ip, dst=DEST_IP) / \
              UDP(sport=random.randint(1024, 65535), dport=DEST_PORT) / \
              payload

        print(f"[DEBUG] Sending encrypted packet:")
        print(f"  - From MAC: {fake_mac}")
        print(f"  - From IP: {fake_ip}")
        print(f"  - Payload size: {len(encrypted_bytes)} bytes")
        print(f"  - To port: {DEST_PORT}")
        
        sendp(pkt, iface=INTERFACE, verbose=False)
        print("[DEBUG] Packet sent successfully!")
        
    except Exception as e:
        print(f"[ERROR] Failed to send packet: {e}")
        import traceback
        traceback.print_exc()

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
