import hashlib

class PeerManager:
    def __init__(self):
        self.peers = {}  # peer_id -> {nickname, public_key}

    def get_peer_id(self, public_key_b64):
        return hashlib.sha256(public_key_b64.encode()).hexdigest()

    def peer_exists(self, public_key_b64):
        """Check if a peer exists based on their public key."""
        peer_id = self.get_peer_id(public_key_b64)
        return peer_id in self.peers

    def add_peer(self, nickname, public_key_b64):
        peer_id = self.get_peer_id(public_key_b64)
        print(f"[DEBUG] PeerManager.add_peer: {nickname}")
        print(f"  - Peer ID: {peer_id[:8]}...")
        print(f"  - Public key length: {len(public_key_b64)}")
        
        # Check if peer already exists
        if peer_id in self.peers:
            print(f"  - Peer {nickname} already exists, updating...")
        else:
            print(f"  - Adding new peer {nickname}")
            
        self.peers[peer_id] = {
            "nickname": nickname,
            "public_key": public_key_b64
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
        for pid in list(self.peers):
            if self.peers[pid]["nickname"] == nickname:
                print(f"[DEBUG] PeerManager.remove_peer: {nickname} (ID: {pid[:8]}...)")
                del self.peers[pid]
                print(f"  - Total peers now: {len(self.peers)}")
                break
        else:
            print(f"[DEBUG] PeerManager.remove_peer: {nickname} not found")

    def clear(self):
        peer_count = len(self.peers)
        self.peers.clear()
        print(f"[DEBUG] PeerManager.clear: Removed {peer_count} peers")
