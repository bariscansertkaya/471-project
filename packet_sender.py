from scapy.all import Ether, IP, UDP, Raw, sendp, get_if_hwaddr, get_if_addr
import random
import uuid
import time
from crypto_utils import load_keys, import_public_key_base64, export_public_key_base64
from message import ChatMessage
from multipart_message import MultipartMessageSender, MessageFragment

# --- Settings ---
INTERFACE = "en0"  # Change this to your active network interface
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
DEST_IP = "255.255.255.255"
DEST_PORT = 42069  # Arbitrary UDP port
FRAGMENT_PORT = 42070  # Port for multi-part messages

# --- MAC/IP Spoofing ---
def generate_fake_mac():
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0x00, 0xFF) for _ in range(5))

def generate_fake_ip():
    return "{}.{}.{}.{}".format(*[random.randint(1, 254) for _ in range(4)])

# --- Multi-part Message Sender ---
multipart_sender = MultipartMessageSender(max_fragment_size=400)

def send_large_encrypted_message(msg: ChatMessage, recipient_pubkey_b64: str, delay_ms: int = 50):
    """
    Send a large encrypted message by splitting it into fragments.
    delay_ms: Delay between sending fragments to avoid overwhelming the network
    """
    print(f"[DEBUG] send_large_encrypted_message called:")
    print(f"  - Message type: {msg.type}")
    print(f"  - Sender: {msg.nickname}")
    print(f"  - Data length: {len(msg.data) if msg.data else 0}")
    print(f"  - Recipient pubkey length: {len(recipient_pubkey_b64) if recipient_pubkey_b64 else 0}")
    
    if not recipient_pubkey_b64:
        print("[ERROR] recipient_pubkey_b64 is None or empty!")
        return False
    
    try:
        # Create message fragments
        fragments = multipart_sender.create_fragments(msg, recipient_pubkey_b64)
        print(f"[DEBUG] Created {len(fragments)} fragments")
        
        # Send each fragment
        success_count = 0
        for i, fragment in enumerate(fragments):
            try:
                success = send_fragment(fragment)
                if success:
                    success_count += 1
                    print(f"[DEBUG] Sent fragment {i + 1}/{len(fragments)}")
                else:
                    print(f"[ERROR] Failed to send fragment {i + 1}/{len(fragments)}")
                
                # Add delay between fragments (except for the last one)
                if i < len(fragments) - 1 and delay_ms > 0:
                    time.sleep(delay_ms / 1000.0)
                    
            except Exception as e:
                print(f"[ERROR] Failed to send fragment {i + 1}: {e}")
        
        print(f"[DEBUG] Successfully sent {success_count}/{len(fragments)} fragments")
        return success_count == len(fragments)
        
    except Exception as e:
        print(f"[ERROR] Failed to create/send large message: {e}")
        import traceback
        traceback.print_exc()
        return False

def send_fragment(fragment: MessageFragment) -> bool:
    """Send a single message fragment."""
    try:
        payload = Raw(load=fragment.to_bytes())
        fake_mac = generate_fake_mac()
        fake_ip = generate_fake_ip()
        
        pkt = Ether(src=fake_mac, dst=BROADCAST_MAC) / \
              IP(src=fake_ip, dst=DEST_IP) / \
              UDP(sport=random.randint(1024, 65535), dport=FRAGMENT_PORT) / \
              payload

        sendp(pkt, iface=INTERFACE, verbose=False)
        return True
        
    except Exception as e:
        print(f"[ERROR] Failed to send fragment: {e}")
        return False

# --- Encrypted Message Sender (for small messages) ---
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
    
    # Check message size - RSA 2048 can only encrypt ~245 bytes max
    message_json = msg.to_json()
    message_size = len(message_json.encode('utf-8'))
    print(f"[DEBUG] Message JSON size: {message_size} bytes")
    
    if message_size > 245:
        print(f"[WARNING] Message too large for direct RSA encryption: {message_size} bytes > 245 byte limit")
        print("[INFO] Switching to large message protocol...")
        return send_large_encrypted_message(msg, recipient_pubkey_b64)
    
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

# --- Auto-routing Message Sender ---
def send_message_auto(msg: ChatMessage, recipient_pubkey_b64: str = None):
    """
    Automatically choose the best sending method based on message size and encryption needs.
    """
    message_json = msg.to_json()
    message_size = len(message_json.encode('utf-8'))
    
    if recipient_pubkey_b64:
        # Encrypted message
        if message_size <= 245:
            print(f"[INFO] Sending small encrypted message ({message_size} bytes)")
            send_encrypted_message(msg, recipient_pubkey_b64)
        else:
            print(f"[INFO] Sending large encrypted message ({message_size} bytes)")
            send_large_encrypted_message(msg, recipient_pubkey_b64)
    else:
        # Raw message (for broadcasts like JOIN)
        print(f"[INFO] Sending raw broadcast message ({message_size} bytes)")
        send_raw_message(msg)

# --- Example Usage ---
if __name__ == "__main__":
    priv, pub = load_keys()
    pub_b64 = export_public_key_base64(pub)

    # Test with a small message
    msg = ChatMessage("chat", "TestUser", "Hello, this is a small test message!")
    send_message_auto(msg, pub_b64)
    
    # Test with a large message
    large_data = "This is a very large message! " * 100  # Create a large message
    large_msg = ChatMessage("chat", "TestUser", large_data)
    send_message_auto(large_msg, pub_b64)
