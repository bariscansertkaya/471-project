import uuid
import time
import json
import threading
from typing import Dict, List, Optional, Tuple
from message import ChatMessage


class MessageFragment:
    """Represents a fragment of a larger message"""
    
    def __init__(self, original_msg_id: str, fragment_id: str, part_idx: int, 
                 total_parts: int, data: str, msg_type: str, nickname: str, 
                 timestamp: int = None, ttl: int = 10):
        self.original_msg_id = original_msg_id  # ID of the original large message
        self.fragment_id = fragment_id or str(uuid.uuid4())  # Unique ID for this fragment
        self.part_idx = part_idx  # 0-based index of this fragment
        self.total_parts = total_parts  # Total number of fragments
        self.data = data  # Fragment data
        self.msg_type = msg_type  # Type of original message
        self.nickname = nickname  # Sender nickname
        self.timestamp = timestamp or int(time.time())
        self.ttl = ttl
    
    def to_chat_message(self) -> ChatMessage:
        """Convert fragment to ChatMessage for network transmission"""
        fragment_data = {
            "original_msg_id": self.original_msg_id,
            "fragment_id": self.fragment_id,
            "part_idx": self.part_idx,
            "total_parts": self.total_parts,
            "fragment_data": self.data,
            "original_type": self.msg_type
        }
        
        return ChatMessage(
            msg_type="fragment",
            nickname=self.nickname,
            data=json.dumps(fragment_data),
            msg_id=self.fragment_id,
            timestamp=self.timestamp,
            ttl=self.ttl
        )
    
    @staticmethod
    def from_chat_message(chat_msg: ChatMessage) -> Optional['MessageFragment']:
        """Create MessageFragment from received ChatMessage"""
        if chat_msg.type != "fragment":
            return None
        
        try:
            fragment_data = json.loads(chat_msg.data)
            return MessageFragment(
                original_msg_id=fragment_data["original_msg_id"],
                fragment_id=fragment_data["fragment_id"],
                part_idx=fragment_data["part_idx"],
                total_parts=fragment_data["total_parts"],
                data=fragment_data["fragment_data"],
                msg_type=fragment_data["original_type"],
                nickname=chat_msg.nickname,
                timestamp=chat_msg.timestamp,
                ttl=chat_msg.ttl
            )
        except (json.JSONDecodeError, KeyError) as e:
            print(f"[FRAGMENT] Error parsing fragment: {e}")
            return None


class PartialMessage:
    """Tracks fragments of a message being reassembled"""
    
    def __init__(self, original_msg_id: str, total_parts: int, msg_type: str, 
                 nickname: str, timestamp: int, ttl: int):
        self.original_msg_id = original_msg_id
        self.total_parts = total_parts
        self.msg_type = msg_type
        self.nickname = nickname
        self.timestamp = timestamp
        self.ttl = ttl
        self.fragments: Dict[int, str] = {}  # part_idx -> fragment_data
        self.created_time = time.time()
        self.last_fragment_time = time.time()
    
    def add_fragment(self, fragment: MessageFragment) -> bool:
        """Add a fragment. Returns True if message is now complete."""
        if fragment.part_idx in self.fragments:
            return False  # Duplicate fragment
        
        self.fragments[fragment.part_idx] = fragment.data
        self.last_fragment_time = time.time()
        
        return len(self.fragments) == self.total_parts
    
    def get_complete_message(self) -> Optional[ChatMessage]:
        """Reassemble fragments into complete message"""
        if len(self.fragments) != self.total_parts:
            return None
        
        # Reassemble data in correct order
        complete_data = ""
        for i in range(self.total_parts):
            if i not in self.fragments:
                return None  # Missing fragment
            complete_data += self.fragments[i]
        
        return ChatMessage(
            msg_type=self.msg_type,
            nickname=self.nickname,
            data=complete_data,
            msg_id=self.original_msg_id,
            timestamp=self.timestamp,
            ttl=self.ttl
        )
    
    def is_expired(self, timeout: float = 300.0) -> bool:
        """Check if partial message has expired (default: 5 minutes)"""
        return time.time() - self.created_time > timeout


class MessageFragmenter:
    """Handles fragmentation and reassembly of large messages"""
    
    def __init__(self, max_fragment_size: int = 200, reassembly_timeout: float = 300.0):
        self.max_fragment_size = max_fragment_size  # Max size per fragment
        self.reassembly_timeout = reassembly_timeout  # Timeout for partial messages
        self.partial_messages: Dict[str, PartialMessage] = {}  # original_msg_id -> PartialMessage
        self.lock = threading.RLock()
        self.cleanup_thread = None
        self.running = False
    
    def start_cleanup_thread(self):
        """Start background cleanup thread for expired partial messages"""
        if self.cleanup_thread is None or not self.cleanup_thread.is_alive():
            self.running = True
            self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
            self.cleanup_thread.start()
            print("[FRAGMENT] Message fragmenter cleanup thread started")
    
    def stop_cleanup_thread(self):
        """Stop background cleanup thread"""
        self.running = False
        if self.cleanup_thread and self.cleanup_thread.is_alive():
            self.cleanup_thread.join(timeout=1)
        print("[FRAGMENT] Message fragmenter cleanup thread stopped")
    
    def needs_fragmentation(self, message: ChatMessage) -> bool:
        """Check if message needs to be fragmented"""
        message_size = len(message.to_json().encode('utf-8'))
        return message_size > self.max_fragment_size
    
    def fragment_message(self, message: ChatMessage) -> List[MessageFragment]:
        """Fragment a large message into smaller pieces"""
        if not self.needs_fragmentation(message):
            return []  # Message doesn't need fragmentation
        
        data = message.data
        fragments = []
        
        # Calculate how much space we have for actual data after JSON overhead
        # Account for JSON structure, original_msg_id, indices, etc.
        overhead = 150  # Estimated JSON overhead
        usable_size = self.max_fragment_size - overhead
        
        if usable_size <= 0:
            raise ValueError("Fragment size too small to accommodate overhead")
        
        # Split data into chunks
        total_parts = (len(data) + usable_size - 1) // usable_size  # Ceiling division
        
        print(f"[FRAGMENT] Splitting message {message.msg_id[:8]}... into {total_parts} parts")
        print(f"[FRAGMENT] Original size: {len(data)} bytes, max fragment data: {usable_size} bytes")
        
        for i in range(total_parts):
            start_idx = i * usable_size
            end_idx = min(start_idx + usable_size, len(data))
            fragment_data = data[start_idx:end_idx]
            
            fragment = MessageFragment(
                original_msg_id=message.msg_id,
                fragment_id=str(uuid.uuid4()),
                part_idx=i,
                total_parts=total_parts,
                data=fragment_data,
                msg_type=message.type,
                nickname=message.nickname,
                timestamp=message.timestamp,
                ttl=message.ttl
            )
            
            fragments.append(fragment)
            print(f"[FRAGMENT] Created fragment {i+1}/{total_parts}, size: {len(fragment_data)} bytes")
        
        return fragments
    
    def process_fragment(self, fragment: MessageFragment) -> Optional[ChatMessage]:
        """Process a received fragment. Returns complete message if reassembly is done."""
        with self.lock:
            original_msg_id = fragment.original_msg_id
            
            print(f"[FRAGMENT] Processing fragment {fragment.part_idx + 1}/{fragment.total_parts} for message {original_msg_id[:8]}...")
            
            # Get or create partial message
            if original_msg_id not in self.partial_messages:
                self.partial_messages[original_msg_id] = PartialMessage(
                    original_msg_id=original_msg_id,
                    total_parts=fragment.total_parts,
                    msg_type=fragment.msg_type,
                    nickname=fragment.nickname,
                    timestamp=fragment.timestamp,
                    ttl=fragment.ttl
                )
                print(f"[FRAGMENT] Started reassembly for message {original_msg_id[:8]}... ({fragment.total_parts} parts expected)")
            
            partial_msg = self.partial_messages[original_msg_id]
            
            # Add fragment
            is_complete = partial_msg.add_fragment(fragment)
            
            if is_complete:
                print(f"[FRAGMENT] Message {original_msg_id[:8]}... reassembly complete!")
                complete_message = partial_msg.get_complete_message()
                
                # Clean up
                del self.partial_messages[original_msg_id]
                
                return complete_message
            else:
                current_parts = len(partial_msg.fragments)
                print(f"[FRAGMENT] Message {original_msg_id[:8]}... progress: {current_parts}/{fragment.total_parts} fragments received")
                return None
    
    def cleanup_expired_messages(self) -> int:
        """Remove expired partial messages. Returns number of cleaned up messages."""
        with self.lock:
            expired_messages = []
            current_time = time.time()
            
            for msg_id, partial_msg in self.partial_messages.items():
                if partial_msg.is_expired(self.reassembly_timeout):
                    expired_messages.append(msg_id)
            
            for msg_id in expired_messages:
                partial_msg = self.partial_messages[msg_id]
                print(f"[FRAGMENT] Cleaning up expired partial message {msg_id[:8]}... ({len(partial_msg.fragments)}/{partial_msg.total_parts} fragments received)")
                del self.partial_messages[msg_id]
            
            return len(expired_messages)
    
    def _cleanup_loop(self):
        """Background cleanup thread loop"""
        while self.running:
            try:
                cleaned = self.cleanup_expired_messages()
                if cleaned > 0:
                    print(f"[FRAGMENT] Cleaned up {cleaned} expired partial messages")
                
                # Sleep for 1 minute between cleanups
                for _ in range(60):
                    if not self.running:
                        break
                    time.sleep(1)
            except Exception as e:
                print(f"[FRAGMENT] Error in cleanup loop: {e}")
                time.sleep(5)
    
    def get_stats(self) -> dict:
        """Get fragmentation statistics"""
        with self.lock:
            total_partial = len(self.partial_messages)
            partial_details = {}
            
            for msg_id, partial_msg in self.partial_messages.items():
                partial_details[msg_id[:8]] = {
                    "fragments_received": len(partial_msg.fragments),
                    "total_expected": partial_msg.total_parts,
                    "age_seconds": time.time() - partial_msg.created_time,
                    "nickname": partial_msg.nickname,
                    "type": partial_msg.msg_type
                }
            
            return {
                "max_fragment_size": self.max_fragment_size,
                "reassembly_timeout": self.reassembly_timeout,
                "partial_messages": total_partial,
                "partial_details": partial_details,
                "running": self.running
            }


# Global instance
_fragmenter = None

def get_message_fragmenter() -> MessageFragmenter:
    """Get global MessageFragmenter instance"""
    global _fragmenter
    if _fragmenter is None:
        _fragmenter = MessageFragmenter()
        _fragmenter.start_cleanup_thread()
    return _fragmenter 