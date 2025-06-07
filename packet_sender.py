from scapy.all import Ether, IP, UDP, Raw, sendp, get_if_hwaddr, get_if_addr
import random
import uuid
from crypto_utils import load_keys, import_public_key_base64, export_public_key_base64
from message import ChatMessage
from message_fragmenter import get_message_fragmenter, MessageFragment

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

# --- Enhanced Encrypted Message Sender with Fragmentation ---
def send_encrypted_message(msg: ChatMessage, recipient_pubkey_b64: str):
    """Send encrypted message with automatic fragmentation for large messages"""
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
    
    # Get fragmenter
    fragmenter = get_message_fragmenter()
    
    if message_size > 245:
        print(f"[DEBUG] Message too large for direct RSA encryption: {message_size} bytes > 245 byte limit")
        print(f"[DEBUG] Using fragmentation for large message")
        
        # Fragment the message
        try:
            fragments = fragmenter.fragment_message(msg)
            if not fragments:
                print("[ERROR] Fragmentation failed - no fragments created")
                return
            
            print(f"[DEBUG] Message fragmented into {len(fragments)} parts")
            
            # Send each fragment as encrypted message
            for i, fragment in enumerate(fragments):
                fragment_chat_msg = fragment.to_chat_message()
                
                # Verify fragment size is within encryption limits
                fragment_json = fragment_chat_msg.to_json()
                fragment_size = len(fragment_json.encode('utf-8'))
                
                if fragment_size > 245:
                    print(f"[ERROR] Fragment {i+1} still too large: {fragment_size} bytes")
                    print(f"[ERROR] Fragment data: {fragment_json[:100]}...")
                    continue
                
                # Encrypt and send fragment
                try:
                    recipient_pubkey = import_public_key_base64(recipient_pubkey_b64)
                    encrypted_bytes = fragment_chat_msg.encrypt(recipient_pubkey)
                    
                    payload = Raw(load=encrypted_bytes)
                    fake_mac = generate_fake_mac()
                    fake_ip = generate_fake_ip()
                    
                    pkt = Ether(src=fake_mac, dst=BROADCAST_MAC) / \
                          IP(src=fake_ip, dst=DEST_IP) / \
                          UDP(sport=random.randint(1024, 65535), dport=DEST_PORT) / \
                          payload

                    print(f"[DEBUG] Sending encrypted fragment {i+1}/{len(fragments)}:")
                    print(f"  - From MAC: {fake_mac}")
                    print(f"  - From IP: {fake_ip}")
                    print(f"  - Fragment size: {fragment_size} bytes")
                    print(f"  - Encrypted size: {len(encrypted_bytes)} bytes")
                    
                    sendp(pkt, iface=INTERFACE, verbose=False)
                    print(f"[DEBUG] Fragment {i+1}/{len(fragments)} sent successfully!")
                    
                except Exception as e:
                    print(f"[ERROR] Failed to encrypt/send fragment {i+1}: {e}")
                    import traceback
                    traceback.print_exc()
                    
            print(f"[DEBUG] All {len(fragments)} fragments sent for message {msg.msg_id[:8]}...")
            return
            
        except Exception as e:
            print(f"[ERROR] Fragmentation failed: {e}")
            import traceback
            traceback.print_exc()
            return
    
    # Original logic for small messages
    try:
        print("[DEBUG] Message fits in single packet, sending directly...")
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

# --- Enhanced Raw Message Sender with Fragmentation ---
def send_raw_message(msg: ChatMessage):
    """Send raw message with automatic fragmentation for large messages"""
    fragmenter = get_message_fragmenter()
    
    # Check if message needs fragmentation
    if fragmenter.needs_fragmentation(msg):
        print(f"[DEBUG] Raw message too large, fragmenting...")
        try:
            fragments = fragmenter.fragment_message(msg)
            if not fragments:
                print("[ERROR] Raw message fragmentation failed - no fragments created")
                return
            
            print(f"[DEBUG] Raw message fragmented into {len(fragments)} parts")
            
            # Send each fragment as raw message
            for i, fragment in enumerate(fragments):
                fragment_chat_msg = fragment.to_chat_message()
                
                try:
                    raw_bytes = fragment_chat_msg.to_bytes()
                    
                    payload = Raw(load=raw_bytes)
                    fake_mac = generate_fake_mac()
                    fake_ip = generate_fake_ip()
                    
                    pkt = Ether(src=fake_mac, dst=BROADCAST_MAC) / \
                          IP(src=fake_ip, dst=DEST_IP) / \
                          UDP(sport=random.randint(1024, 65535), dport=DEST_PORT) / \
                          payload

                    print(f"[*] Sending RAW fragment {i+1}/{len(fragments)} from {fake_ip} / {fake_mac}")
                    sendp(pkt, iface=INTERFACE, verbose=False)
                    
                except Exception as e:
                    print(f"[!] Failed to send raw fragment {i+1}: {e}")
                    
            print(f"[DEBUG] All {len(fragments)} raw fragments sent for message {msg.msg_id[:8]}...")
            return
            
        except Exception as e:
            print(f"[ERROR] Raw message fragmentation failed: {e}")
            import traceback
            traceback.print_exc()
            return
    
    # Original logic for small messages
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

# --- Broadcast Encrypted Message to Multiple Recipients ---
def send_encrypted_broadcast(msg: ChatMessage, recipient_pubkeys: dict):
    """Send encrypted message to multiple recipients (broadcast encryption)"""
    print(f"[DEBUG] Broadcasting encrypted message to {len(recipient_pubkeys)} recipients")
    
    success_count = 0
    for nickname, pubkey_b64 in recipient_pubkeys.items():
        try:
            print(f"[DEBUG] Sending to {nickname}...")
            send_encrypted_message(msg, pubkey_b64)
            success_count += 1
        except Exception as e:
            print(f"[ERROR] Failed to send to {nickname}: {e}")
    
    print(f"[DEBUG] Broadcast complete: {success_count}/{len(recipient_pubkeys)} successful")
    return success_count

# --- Example Usage ---
if __name__ == "__main__":
    priv, pub = load_keys()
    pub_b64 = export_public_key_base64(pub)

    # Test small message
    msg = ChatMessage("chat", "xxBarisxx", "Hello World!")
    send_raw_message(msg)
    
    # Test large message
    large_data = "A" * 1000  # 1000 character message
    large_msg = ChatMessage("chat", "xxBarisxx", large_data)
    send_encrypted_message(large_msg, pub_b64)
