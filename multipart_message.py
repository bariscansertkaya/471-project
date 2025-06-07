import uuid
import time
import json
import threading
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from crypto_utils import encrypt_large_message, decrypt_large_message, import_public_key_base64
from message import ChatMessage


@dataclass
class MessageFragment:
    """Represents a fragment of a large message."""
    message_id: str
    fragment_id: int
    total_fragments: int
    encrypted_aes_key: bytes  # RSA-encrypted AES key (only in first fragment)
    encrypted_data: bytes     # AES-encrypted message fragment
    timestamp: float
    sender: str
    message_type: str

    def to_dict(self) -> dict:
        return {
            "message_id": self.message_id,
            "fragment_id": self.fragment_id,
            "total_fragments": self.total_fragments,
            "encrypted_aes_key": self.encrypted_aes_key.hex() if self.encrypted_aes_key else "",
            "encrypted_data": self.encrypted_data.hex(),
            "timestamp": self.timestamp,
            "sender": self.sender,
            "message_type": self.message_type
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    def to_bytes(self) -> bytes:
        return self.to_json().encode("utf-8")

    @staticmethod
    def from_bytes(data: bytes) -> Optional['MessageFragment']:
        try:
            obj = json.loads(data.decode("utf-8"))
            return MessageFragment(
                message_id=obj["message_id"],
                fragment_id=obj["fragment_id"],
                total_fragments=obj["total_fragments"],
                encrypted_aes_key=bytes.fromhex(obj["encrypted_aes_key"]) if obj["encrypted_aes_key"] else b"",
                encrypted_data=bytes.fromhex(obj["encrypted_data"]),
                timestamp=obj["timestamp"],
                sender=obj["sender"],
                message_type=obj["message_type"]
            )
        except Exception as e:
            print(f"[!] Failed to parse MessageFragment: {e}")
            return None


class MultipartMessageAssembler:
    """Handles assembly of multi-part messages."""
    
    def __init__(self, private_key, timeout_seconds: int = 60):
        self.private_key = private_key
        self.timeout_seconds = timeout_seconds
        self.pending_messages: Dict[str, Dict[int, MessageFragment]] = {}
        self.message_metadata: Dict[str, Tuple[int, float]] = {}  # total_fragments, first_seen_time
        self.lock = threading.Lock()
        
        # Start cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_expired_messages, daemon=True)
        self.cleanup_thread.start()

    def add_fragment(self, fragment: MessageFragment) -> Optional[ChatMessage]:
        """
        Add a message fragment. Returns complete ChatMessage if all fragments received.
        """
        with self.lock:
            message_id = fragment.message_id
            
            # Initialize message tracking if first fragment
            if message_id not in self.pending_messages:
                self.pending_messages[message_id] = {}
                self.message_metadata[message_id] = (fragment.total_fragments, time.time())
                print(f"[DEBUG] Started tracking message {message_id[:8]}... ({fragment.total_fragments} fragments)")
            
            # Add fragment
            self.pending_messages[message_id][fragment.fragment_id] = fragment
            current_count = len(self.pending_messages[message_id])
            total_count = self.message_metadata[message_id][0]
            
            print(f"[DEBUG] Received fragment {fragment.fragment_id + 1}/{total_count} for message {message_id[:8]}...")
            
            # Check if we have all fragments
            if current_count == total_count:
                print(f"[DEBUG] All fragments received for message {message_id[:8]}..., assembling...")
                try:
                    complete_message = self._assemble_message(message_id)
                    # Clean up
                    del self.pending_messages[message_id]
                    del self.message_metadata[message_id]
                    return complete_message
                except Exception as e:
                    print(f"[!] Failed to assemble message {message_id[:8]}...: {e}")
                    # Clean up failed message
                    del self.pending_messages[message_id]
                    del self.message_metadata[message_id]
            
            return None

    def _assemble_message(self, message_id: str) -> ChatMessage:
        """Assemble fragments into a complete message."""
        fragments = self.pending_messages[message_id]
        
        # Sort fragments by fragment_id
        sorted_fragments = [fragments[i] for i in sorted(fragments.keys())]
        
        # Get encrypted AES key from first fragment
        encrypted_aes_key = sorted_fragments[0].encrypted_aes_key
        if not encrypted_aes_key:
            raise ValueError("Missing encrypted AES key in first fragment")
        
        # Combine all encrypted data
        combined_encrypted_data = b"".join(frag.encrypted_data for frag in sorted_fragments)
        
        # Decrypt the complete message
        decrypted_json = decrypt_large_message(self.private_key, encrypted_aes_key, combined_encrypted_data)
        
        # Parse back to ChatMessage
        return ChatMessage.from_json(decrypted_json)

    def _cleanup_expired_messages(self):
        """Background thread to cleanup expired incomplete messages."""
        while True:
            time.sleep(30)  # Check every 30 seconds
            current_time = time.time()
            
            with self.lock:
                expired_ids = []
                for message_id, (_, first_seen) in self.message_metadata.items():
                    if current_time - first_seen > self.timeout_seconds:
                        expired_ids.append(message_id)
                
                for message_id in expired_ids:
                    print(f"[DEBUG] Cleaning up expired incomplete message {message_id[:8]}...")
                    del self.pending_messages[message_id]
                    del self.message_metadata[message_id]

    def get_status(self) -> Dict[str, Dict]:
        """Get status of pending messages for debugging."""
        with self.lock:
            status = {}
            for message_id, (total, first_seen) in self.message_metadata.items():
                current_count = len(self.pending_messages[message_id])
                age = time.time() - first_seen
                status[message_id[:8]] = {
                    "fragments_received": current_count,
                    "total_fragments": total,
                    "age_seconds": round(age, 1),
                    "complete": current_count == total
                }
            return status


class MultipartMessageSender:
    """Handles splitting and sending large messages."""
    
    def __init__(self, max_fragment_size: int = 1024):
        """
        Initialize sender.
        max_fragment_size: Maximum size of each fragment's encrypted data in bytes
        """
        self.max_fragment_size = max_fragment_size

    def create_fragments(self, message: ChatMessage, recipient_public_key_b64: str) -> List[MessageFragment]:
        """
        Split a large message into encrypted fragments.
        """
        try:
            recipient_public_key = import_public_key_base64(recipient_public_key_b64)
        except Exception as e:
            raise ValueError(f"Invalid recipient public key: {e}")
        
        # Encrypt the entire message using hybrid encryption
        message_json = message.to_json()
        encrypted_aes_key, encrypted_data = encrypt_large_message(recipient_public_key, message_json)
        
        # Calculate number of fragments needed
        total_fragments = (len(encrypted_data) + self.max_fragment_size - 1) // self.max_fragment_size
        
        # Generate unique message ID
        message_id = str(uuid.uuid4())
        timestamp = time.time()
        
        print(f"[DEBUG] Splitting message into {total_fragments} fragments (total encrypted size: {len(encrypted_data)} bytes)")
        
        fragments = []
        for i in range(total_fragments):
            start_idx = i * self.max_fragment_size
            end_idx = min((i + 1) * self.max_fragment_size, len(encrypted_data))
            fragment_data = encrypted_data[start_idx:end_idx]
            
            # Only include encrypted AES key in the first fragment
            frag_aes_key = encrypted_aes_key if i == 0 else b""
            
            fragment = MessageFragment(
                message_id=message_id,
                fragment_id=i,
                total_fragments=total_fragments,
                encrypted_aes_key=frag_aes_key,
                encrypted_data=fragment_data,
                timestamp=timestamp,
                sender=message.nickname,
                message_type=message.type
            )
            
            fragments.append(fragment)
        
        return fragments 