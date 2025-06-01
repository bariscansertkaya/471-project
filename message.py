import uuid
import time
import json
from crypto_utils import encrypt_message, decrypt_message


class ChatMessage:
    def __init__(self, msg_type: str, nickname: str, data: str, msg_id=None, timestamp=None):
        self.type = msg_type  # e.g. 'chat', 'join', 'quit'
        self.nickname = nickname
        self.data = data  # Plaintext message content
        self.msg_id = msg_id or str(uuid.uuid4())
        self.timestamp = timestamp or int(time.time())

    def to_dict(self):
        return {
            "type": self.type,
            "nickname": self.nickname,
            "msg_id": self.msg_id,
            "timestamp": self.timestamp,
            "data": self.data  # Still plaintext here
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @staticmethod
    def from_json(json_str: str):
        try:
            obj = json.loads(json_str)
            return ChatMessage(
                msg_type=obj["type"],
                nickname=obj["nickname"],
                data=obj["data"],
                msg_id=obj.get("msg_id"),
                timestamp=obj.get("timestamp")
            )
        except Exception as e:
            print("[!] Failed to parse message:", e)
            return None

    def encrypt(self, recipient_public_key) -> bytes:
        """
        Returns encrypted bytes ready to be packed into a Scapy packet.
        """
        return encrypt_message(recipient_public_key, self.to_json())

    @staticmethod
    def decrypt(ciphertext: bytes, private_key):
        """
        Decrypts raw encrypted data and returns a ChatMessage object.
        """
        try:
            plaintext = decrypt_message(private_key, ciphertext)
            return ChatMessage.from_json(plaintext)
        except Exception as e:
            print("[!] Failed to decrypt message:", e)
            return None
