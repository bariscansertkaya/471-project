import hashlib

class PeerManager:
    def __init__(self):
        self.peers = {}  # peer_id -> {nickname, public_key}

    def get_peer_id(self, public_key_b64):
        return hashlib.sha256(public_key_b64.encode()).hexdigest()

    def add_peer(self, nickname, public_key_b64):
        peer_id = self.get_peer_id(public_key_b64)
        self.peers[peer_id] = {
            "nickname": nickname,
            "public_key": public_key_b64
        }

    def get_nickname(self, public_key_b64):
        peer_id = self.get_peer_id(public_key_b64)
        return self.peers.get(peer_id, {}).get("nickname", None)

    def get_public_key(self, nickname):
        for p in self.peers.values():
            if p["nickname"] == nickname:
                return p["public_key"]
        return None

    def remove_peer(self, nickname):
        for pid in list(self.peers):
            if self.peers[pid]["nickname"] == nickname:
                del self.peers[pid]
                break

    def clear(self):
        self.peers.clear()
