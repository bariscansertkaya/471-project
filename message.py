import uuid
import time
import json
from crypto_utils import encrypt_message, decrypt_message


class ChatMessage:
    def __init__(self, msg_type: str, nickname: str, data: str, msg_id=None, timestamp=None, ttl: int = 10):
        self.type = msg_type  # e.g. 'chat', 'join', 'quit'
        self.nickname = nickname
        self.data = data  # Plaintext message content
        self.msg_id = msg_id or str(uuid.uuid4())
        self.timestamp = timestamp or int(time.time())
        self.ttl = ttl  # Time To Live (hop count)

    def to_dict(self):
        return {
            "type": self.type,
            "nickname": self.nickname,
            "msg_id": self.msg_id,
            "timestamp": self.timestamp,
            "data": self.data,
            "ttl": self.ttl
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    def to_bytes(self) -> bytes:
        return self.to_json().encode("utf-8")

    @staticmethod
    def from_bytes(byte_data: bytes):
        try:
            return ChatMessage.from_json(byte_data.decode("utf-8"))
        except Exception as e:
            print("[!] Failed to deserialize from bytes:", e)
            return None

    @staticmethod
    def from_json(json_str: str):
        try:
            obj = json.loads(json_str)
            return ChatMessage(
                msg_type=obj["type"],
                nickname=obj["nickname"],
                data=obj["data"],
                msg_id=obj.get("msg_id"),
                timestamp=obj.get("timestamp"),
                ttl=obj.get("ttl", 10)
            )
        except Exception as e:
            print("[!] Failed to parse message:", e)
            return None

    def encrypt(self, recipient_public_key) -> bytes:
        return encrypt_message(recipient_public_key, self.to_json())

    @staticmethod
    def decrypt(ciphertext: bytes, private_key):
        try:
            plaintext = decrypt_message(private_key, ciphertext)
            return ChatMessage.from_json(plaintext)
        except Exception as e:
            print("[!] Failed to decrypt message:", e)
            return None

    def decrement_ttl(self) -> bool:
        """
        Decrement TTL by 1. Returns True if message should continue, False if expired.
        """
        self.ttl -= 1
        return self.ttl > 0

    def is_expired(self) -> bool:
        """Check if message TTL has expired"""
        return self.ttl <= 0

    def copy_with_decremented_ttl(self):
        """Create a copy of the message with TTL decremented"""
        new_msg = ChatMessage(
            msg_type=self.type,
            nickname=self.nickname,
            data=self.data,
            msg_id=self.msg_id,
            timestamp=self.timestamp,
            ttl=self.ttl - 1
        )
        return new_msg
