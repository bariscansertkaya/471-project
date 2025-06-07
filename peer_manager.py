import hashlib
import time
import threading

class PeerManager:
    def __init__(self, peer_timeout_seconds=300, inactive_callback=None):  # 5 minutes default timeout
        self.peers = {}  # peer_id -> {nickname, public_key, last_seen}
        self.peer_timeout_seconds = peer_timeout_seconds
        self.inactive_callback = inactive_callback  # Callback for when peers become inactive
        self.lock = threading.Lock()
        
        # Start cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_inactive_peers, daemon=True)
        self.cleanup_thread.start()

    def get_peer_id(self, public_key_b64):
        return hashlib.sha256(public_key_b64.encode()).hexdigest()

    def peer_exists(self, public_key_b64):
        """Check if a peer exists based on their public key."""
        peer_id = self.get_peer_id(public_key_b64)
        return peer_id in self.peers

    def add_peer(self, nickname, public_key_b64):
        with self.lock:
            peer_id = self.get_peer_id(public_key_b64)
            current_time = time.time()
            
            print(f"[DEBUG] PeerManager.add_peer: {nickname}")
            print(f"  - Peer ID: {peer_id[:8]}...")
            print(f"  - Public key length: {len(public_key_b64)}")
            
            # Check if peer already exists
            if peer_id in self.peers:
                print(f"  - Peer {nickname} already exists, updating last_seen...")
            else:
                print(f"  - Adding new peer {nickname}")
                
            self.peers[peer_id] = {
                "nickname": nickname,
                "public_key": public_key_b64,
                "last_seen": current_time
            }
            print(f"  - Total peers now: {len(self.peers)}")

    def get_nickname(self, public_key_b64):
        peer_id = self.get_peer_id(public_key_b64)
        result = self.peers.get(peer_id, {}).get("nickname", None)
        print(f"[DEBUG] PeerManager.get_nickname for {peer_id[:8]}...: {result}")
        return result

    def get_public_key(self, nickname):
        for p in self.peers.values():
            if p["nickname"] == nickname:
                print(f"[DEBUG] PeerManager.get_public_key for {nickname}: found")
                return p["public_key"]
        print(f"[DEBUG] PeerManager.get_public_key for {nickname}: not found")
        return None

    def remove_peer(self, nickname):
        with self.lock:
            for pid in list(self.peers):
                if self.peers[pid]["nickname"] == nickname:
                    print(f"[DEBUG] PeerManager.remove_peer: {nickname} (ID: {pid[:8]}...)")
                    del self.peers[pid]
                    print(f"  - Total peers now: {len(self.peers)}")
                    break
            else:
                print(f"[DEBUG] PeerManager.remove_peer: {nickname} not found")

    def clear(self):
        with self.lock:
            peer_count = len(self.peers)
            self.peers.clear()
            print(f"[DEBUG] PeerManager.clear: Removed {peer_count} peers")

    def update_peer_activity(self, nickname):
        """Update last_seen timestamp for a peer when they send a message."""
        with self.lock:
            for peer_id, peer_info in self.peers.items():
                if peer_info["nickname"] == nickname:
                    peer_info["last_seen"] = time.time()
                    print(f"[DEBUG] Updated activity for {nickname}")
                    break

    def _cleanup_inactive_peers(self):
        """Background thread to remove inactive peers."""
        while True:
            time.sleep(60)  # Check every minute
            current_time = time.time()
            
            with self.lock:
                inactive_peers = []
                for peer_id, peer_info in self.peers.items():
                    if current_time - peer_info["last_seen"] > self.peer_timeout_seconds:
                        inactive_peers.append((peer_id, peer_info["nickname"]))
                
                for peer_id, nickname in inactive_peers:
                    print(f"[DEBUG] Removing inactive peer: {nickname} (timeout: {self.peer_timeout_seconds}s)")
                    del self.peers[peer_id]
                    
                    # Notify the app about inactive peer
                    if self.inactive_callback:
                        try:
                            self.inactive_callback(nickname)
                        except Exception as e:
                            print(f"[ERROR] Failed to notify about inactive peer {nickname}: {e}")

    def get_inactive_peer_callback(self):
        """Return a callback function for the main app to handle inactive peer notifications."""
        def notify_inactive_peer(nickname):
            # This will be called when a peer is removed due to inactivity
            return nickname
        return notify_inactive_peer
