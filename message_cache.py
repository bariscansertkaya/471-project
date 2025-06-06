import time
import threading
from typing import Dict, Set
from collections import defaultdict


class MessageCache:
    """
    Message cache for preventing loops and duplicate messages.
    Tracks seen message IDs with timestamps and provides cleanup functionality.
    """
    
    def __init__(self, cache_timeout: int = 300):  # 5 minutes default
        self.cache_timeout = cache_timeout  # seconds
        self.seen_messages: Dict[str, float] = {}  # msg_id -> timestamp
        self.gateway_paths: Dict[str, Set[str]] = defaultdict(set)  # msg_id -> set of gateway IPs
        self.lock = threading.RLock()
        self.cleanup_thread = None
        self.running = False
        
    def start_cleanup_thread(self):
        """Start the background cleanup thread"""
        if self.cleanup_thread is None or not self.cleanup_thread.is_alive():
            self.running = True
            self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
            self.cleanup_thread.start()
            print("[CACHE] Message cache cleanup thread started")
            
    def stop_cleanup_thread(self):
        """Stop the background cleanup thread"""
        self.running = False
        if self.cleanup_thread and self.cleanup_thread.is_alive():
            self.cleanup_thread.join(timeout=1)
        print("[CACHE] Message cache cleanup thread stopped")
        
    def is_message_seen(self, msg_id: str) -> bool:
        """Check if a message ID has been seen before"""
        with self.lock:
            if msg_id in self.seen_messages:
                # Check if the cached entry is still valid
                if time.time() - self.seen_messages[msg_id] < self.cache_timeout:
                    return True
                else:
                    # Entry expired, remove it
                    self.remove_message(msg_id)
                    return False
            return False
            
    def add_message(self, msg_id: str, gateway_path: list = None) -> bool:
        """
        Add a message to the cache.
        Returns True if message was added (not a duplicate), False if already exists.
        """
        with self.lock:
            if self.is_message_seen(msg_id):
                return False  # Duplicate message
                
            current_time = time.time()
            self.seen_messages[msg_id] = current_time
            
            # Track gateway path for this message
            if gateway_path:
                self.gateway_paths[msg_id] = set(gateway_path)
            
            print(f"[CACHE] Added message {msg_id[:8]}... to cache")
            return True
            
    def should_forward_to_gateway(self, msg_id: str, target_gateway: str) -> bool:
        """
        Check if a message should be forwarded to a specific gateway.
        Returns False if the gateway is already in the message's path.
        """
        with self.lock:
            if msg_id in self.gateway_paths:
                if target_gateway in self.gateway_paths[msg_id]:
                    print(f"[CACHE] Preventing loop: {target_gateway} already in path for {msg_id[:8]}...")
                    return False
            return True
            
    def add_gateway_to_path(self, msg_id: str, gateway_ip: str):
        """Add a gateway to the path of a message"""
        with self.lock:
            self.gateway_paths[msg_id].add(gateway_ip)
            print(f"[CACHE] Added gateway {gateway_ip} to path for message {msg_id[:8]}...")
            
    def remove_message(self, msg_id: str):
        """Remove a message from the cache"""
        with self.lock:
            if msg_id in self.seen_messages:
                del self.seen_messages[msg_id]
            if msg_id in self.gateway_paths:
                del self.gateway_paths[msg_id]
                
    def cleanup_expired_messages(self) -> int:
        """Remove expired messages from cache. Returns number of removed messages."""
        current_time = time.time()
        expired_messages = []
        
        with self.lock:
            for msg_id, timestamp in self.seen_messages.items():
                if current_time - timestamp >= self.cache_timeout:
                    expired_messages.append(msg_id)
                    
            for msg_id in expired_messages:
                self.remove_message(msg_id)
                
        if expired_messages:
            print(f"[CACHE] Cleaned up {len(expired_messages)} expired messages")
            
        return len(expired_messages)
        
    def _cleanup_loop(self):
        """Background cleanup thread loop"""
        while self.running:
            try:
                self.cleanup_expired_messages()
                # Sleep for 1 minute between cleanups
                for _ in range(60):
                    if not self.running:
                        break
                    time.sleep(1)
            except Exception as e:
                print(f"[CACHE] Error in cleanup loop: {e}")
                time.sleep(5)  # Wait before retrying
                
    def get_cache_stats(self) -> dict:
        """Get cache statistics"""
        with self.lock:
            return {
                'total_messages': len(self.seen_messages),
                'total_paths': len(self.gateway_paths),
                'cache_timeout': self.cache_timeout,
                'oldest_message_age': min(
                    [time.time() - ts for ts in self.seen_messages.values()], 
                    default=0
                ),
                'running': self.running
            }
            
    def clear_cache(self):
        """Clear all cached messages"""
        with self.lock:
            self.seen_messages.clear()
            self.gateway_paths.clear()
            print("[CACHE] Message cache cleared")


# Global message cache instance
global_message_cache = MessageCache()


def get_message_cache() -> MessageCache:
    """Get the global message cache instance"""
    return global_message_cache 