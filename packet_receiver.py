from scapy.all import sniff, Raw
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from crypto_utils import load_keys
from message import ChatMessage
from multipart_message import MultipartMessageAssembler, MessageFragment
from peer_manager import PeerManager
import base64

# --- Settings ---
INTERFACE = "bridge100"  # Change to your network interface
DEST_PORT = 42069  # Must match sender for regular messages
FRAGMENT_PORT = 42070  # Must match sender for fragment messages

class PacketReceiver:
    """Enhanced packet receiver that handles both regular and multi-part messages."""
    
    def __init__(self, private_key, message_callback=None):
        self.private_key = private_key
        self.message_callback = message_callback  # Function to call when complete message received
        self.assembler = MultipartMessageAssembler(private_key)
        self.running = False

    def handle_regular_packet(self, packet):
        """Handle regular (non-fragment) packets."""
        if not packet.haslayer(Raw):
            return

        raw_data = packet[Raw].load
        print(f"[DEBUG] Regular packet: Received packet with {len(raw_data)} bytes")

        # Try encrypted message first
        try:
            print("[DEBUG] Attempting to decrypt message...")
            message = ChatMessage.decrypt(raw_data, self.private_key)
            if message:
                print(f"[DEBUG] Successfully decrypted {message.type} message from {message.nickname}")
                if self.message_callback:
                    self.message_callback(message.nickname, message.type, message.data)
                return
        except Exception as e:
            print(f"[DEBUG] Decryption failed (this is normal for raw messages): {e}")

        # Try raw message
        try:
            print("[DEBUG] Attempting to parse as raw message...")
            message = ChatMessage.from_bytes(raw_data)
            if message:
                print(f"[DEBUG] Successfully parsed raw {message.type} message from {message.nickname}")
                if self.message_callback:
                    self.message_callback(message.nickname, message.type, message.data)
                return
        except Exception as e:
            print(f"[DEBUG] Raw message parsing failed: {e}")
            
        print("[DEBUG] Regular packet could not be parsed as either encrypted or raw message")

    def handle_fragment_packet(self, packet):
        """Handle fragment packets for multi-part messages."""
        if not packet.haslayer(Raw):
            return

        raw_data = packet[Raw].load
        print(f"[DEBUG] Fragment packet: Received packet with {len(raw_data)} bytes")

        # Try to parse as message fragment
        try:
            fragment = MessageFragment.from_bytes(raw_data)
            if fragment:
                print(f"[DEBUG] Successfully parsed fragment {fragment.fragment_id + 1}/{fragment.total_fragments} from {fragment.sender}")
                
                # Add fragment to assembler
                complete_message = self.assembler.add_fragment(fragment)
                
                if complete_message:
                    print(f"[DEBUG] Multi-part message assembled! Type: {complete_message.type}, Sender: {complete_message.nickname}")
                    if self.message_callback:
                        self.message_callback(complete_message.nickname, complete_message.type, complete_message.data)
                return
        except Exception as e:
            print(f"[DEBUG] Fragment parsing failed: {e}")
            
        print("[DEBUG] Fragment packet could not be parsed")

    def start_sniffing(self):
        """Start listening for both regular and fragment packets."""
        self.running = True
        print(f"[*] Listening for messages on interface '{INTERFACE}'...")
        print(f"[*] Regular messages on port {DEST_PORT}")
        print(f"[*] Fragment messages on port {FRAGMENT_PORT}")
        
        try:
            # Start sniffing both ports
            sniff(
                iface=INTERFACE,
                prn=self._handle_packet,
                filter=f"udp port {DEST_PORT} or udp port {FRAGMENT_PORT}",
                stop_filter=lambda x: not self.running,
                store=False
            )
        except Exception as e:
            print(f"[!] Packet receiver error: {e}")

    def _handle_packet(self, packet):
        """Route packets to appropriate handlers based on destination port."""
        if packet.haslayer(UDP):
            dest_port = packet[UDP].dport
            if dest_port == DEST_PORT:
                self.handle_regular_packet(packet)
            elif dest_port == FRAGMENT_PORT:
                self.handle_fragment_packet(packet)

    def stop(self):
        """Stop listening for packets."""
        self.running = False

    def get_assembler_status(self):
        """Get status of pending multi-part messages."""
        return self.assembler.get_status()

# --- Legacy Message Handler Function (for compatibility) ---
def handle_packet(self, packet):
    """Legacy function for backwards compatibility."""
    if not packet.haslayer(Raw):
        return

    raw_data = packet[Raw].load

    # 1. Try to decrypt first
    try:
        message = ChatMessage.decrypt(raw_data, self.private_key)
        if message:
            self.message_received.emit(message.nickname, message.type, message.data)
        return
    except Exception as e:
        pass

    # 2. Try raw message
    try:
        message = ChatMessage.from_bytes(raw_data)
        if message:
            self.message_received.emit(message.nickname, message.type, message.data)
    except Exception as e:
        print(f"[!] Failed to parse raw message: {e}")

# --- Main Sniffer (for standalone usage) ---
def start_sniffing():
    """Legacy function for standalone usage."""
    private_key, _ = load_keys()
    receiver = PacketReceiver(private_key)
    receiver.start_sniffing()

# --- Entry Point ---
if __name__ == "__main__":
    start_sniffing()
