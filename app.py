from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QTextEdit, QLineEdit, QPushButton,
    QVBoxLayout, QHBoxLayout, QWidget, QListWidget, QMessageBox, QInputDialog
)
from PyQt6.QtGui import QAction
from PyQt6.QtCore import Qt, QThread, pyqtSignal
import platform
import sys
import os
import time
from scapy.all import sniff, Raw

from crypto_utils import generate_key_pair, load_keys, export_public_key_base64
from message import ChatMessage
from packet_sender import send_encrypted_message, send_raw_message
from packet_receiver import INTERFACE, DEST_PORT
from peer_manager import PeerManager


class NetworkReceiver(QThread):
    message_received = pyqtSignal(str, str, str)  # nickname, type, data

    def __init__(self, private_key):
        super().__init__()
        self.private_key = private_key
        self.running = False

    def handle_packet(self, packet):
        if not packet.haslayer(Raw):
            return
        
        raw_data = packet[Raw].load
        print(f"[DEBUG] NetworkReceiver: Received packet with {len(raw_data)} bytes")
        
        # Try encrypted message first
        try:
            print("[DEBUG] Attempting to decrypt message...")
            message = ChatMessage.decrypt(raw_data, self.private_key)
            if message:
                print(f"[DEBUG] Successfully decrypted {message.type} message from {message.nickname}")
                self.message_received.emit(message.nickname, message.type, message.data)
                return
        except Exception as e:
            print(f"[DEBUG] Decryption failed (this is normal for raw messages): {e}")

        # Try raw message
        try:
            print("[DEBUG] Attempting to parse as raw message...")
            message = ChatMessage.from_bytes(raw_data)
            if message:
                print(f"[DEBUG] Successfully parsed raw {message.type} message from {message.nickname}")
                self.message_received.emit(message.nickname, message.type, message.data)
                return
        except Exception as e:
            print(f"[DEBUG] Raw message parsing failed: {e}")
            
        print("[DEBUG] Packet could not be parsed as either encrypted or raw message")

    def run(self):
        self.running = True
        try:
            sniff(
                iface=INTERFACE,
                prn=self.handle_packet,
                filter=f"udp port {DEST_PORT}",
                stop_filter=lambda x: not self.running,
                store=False
            )
        except Exception as e:
            print(f"[!] Network receiver error: {e}")

    def stop(self):
        self.running = False


class ChatWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Anonymous Chat Network")
        self.resize(800, 600)

        self.private_key = None
        self.public_key = None
        self.nickname = None
        self.is_connected = False
        self.is_gateway_mode = False
        self.network_receiver = None
        self.peer_manager = PeerManager()

        self.init_ui()
        self.load_existing_keys()

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        self.chat_display.append("🔐 Anonymous P2P Chat Network")
        self.chat_display.append("📝 Use File > Generate Keys to create your key pair")
        self.chat_display.append("🌐 Use File > Connect to Network to start chatting")

        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Type your message... (Connect to network first)")
        self.message_input.setEnabled(False)
        self.message_input.returnPressed.connect(self.send_message)

        self.send_button = QPushButton("Send")
        self.send_button.clicked.connect(self.send_message)
        self.send_button.setEnabled(False)

        self.user_list = QListWidget()
        self.user_list.addItem("📡 Network Status: Disconnected")

        input_layout = QHBoxLayout()
        input_layout.addWidget(self.message_input)
        input_layout.addWidget(self.send_button)

        main_layout = QHBoxLayout()
        left_layout = QVBoxLayout()
        left_layout.addWidget(self.chat_display)
        left_layout.addLayout(input_layout)

        main_layout.addLayout(left_layout, 3)
        main_layout.addWidget(self.user_list, 1)

        central_widget.setLayout(main_layout)
        self.setup_menus()

    def setup_menus(self):
        self.menu_bar = self.menuBar()
        if platform.system() == 'Darwin':
            self.menu_bar.setNativeMenuBar(False)

        file_menu = self.menu_bar.addMenu("File")
        preferences_menu = self.menu_bar.addMenu("Preferences")
        help_menu = self.menu_bar.addMenu("Help")

        self.action_generate_keys = QAction("Generate Keys", self)
        self.action_generate_keys.triggered.connect(self.generate_keys)

        self.action_connect = QAction("Connect to Network", self)
        self.action_connect.triggered.connect(self.connect_to_network)

        self.action_disconnect = QAction("Disconnect from Network", self)
        self.action_disconnect.triggered.connect(self.disconnect_from_network)
        self.action_disconnect.setEnabled(False)

        self.action_exit = QAction("&Exit", self)
        self.action_exit.triggered.connect(self.close)

        self.action_toggle_mode = QAction("Toggle Client/Gateway Mode", self)
        self.action_toggle_mode.triggered.connect(self.toggle_mode)

        self.action_about = QAction("About Developer", self)
        self.action_about.triggered.connect(self.show_about)

        self.action_show_debug_info = QAction("Show Debug Info", self)
        self.action_show_debug_info.triggered.connect(self.show_debug_info)

        file_menu.addAction(self.action_generate_keys)
        file_menu.addAction(self.action_connect)
        file_menu.addAction(self.action_disconnect)
        file_menu.addSeparator()
        file_menu.addAction(self.action_exit)

        preferences_menu.addAction(self.action_toggle_mode)
        help_menu.addAction(self.action_about)
        help_menu.addAction(self.action_show_debug_info)

    def load_existing_keys(self):
        try:
            if os.path.exists("keys/privkey.pem") and os.path.exists("keys/pubkey.pem"):
                self.private_key, self.public_key = load_keys()
                self.chat_display.append("✅ Existing key pair loaded successfully")
                self.action_connect.setEnabled(True)
            else:
                self.chat_display.append("⚠️ No existing keys found. Generate new keys first.")
                self.action_connect.setEnabled(False)
        except Exception as e:
            self.chat_display.append(f"❌ Error loading keys: {e}")
            self.action_connect.setEnabled(False)

    def generate_keys(self):
        try:
            self.chat_display.append("🔑 Generating RSA 2048-bit key pair...")
            QApplication.processEvents()
            self.private_key, self.public_key = generate_key_pair()
            self.chat_display.append("✅ Key pair generated and saved successfully!")
            self.chat_display.append("🔐 Your keys are stored in the 'keys' directory")
            self.action_connect.setEnabled(True)
        except Exception as e:
            QMessageBox.critical(self, "Key Generation Error", f"Failed to generate keys: {e}")

    def connect_to_network(self):
        if not self.private_key or not self.public_key:
            QMessageBox.warning(self, "No Keys", "Please generate keys first!")
            return

        nickname, ok = QInputDialog.getText(self, "Connect to Network", "Enter your nickname:")
        if not ok or not nickname.strip():
            return

        self.nickname = nickname.strip()

        try:
            self.network_receiver = NetworkReceiver(self.private_key)
            self.network_receiver.message_received.connect(self.on_message_received)
            self.network_receiver.start()

            self.is_connected = True
            self.message_input.setEnabled(True)
            self.send_button.setEnabled(True)
            self.message_input.setPlaceholderText(f"Type your message as {self.nickname}...")

            self.action_connect.setEnabled(False)
            self.action_disconnect.setEnabled(True)

            self.user_list.clear()
            self.user_list.addItem("📡 Network Status: Connected")
            self.user_list.addItem(f"👤 {self.nickname} (Me)")

            self.send_join_message()

            self.chat_display.append(f"🌐 Connected to network as '{self.nickname}'")
            self.chat_display.append("💡 You can now send and receive messages!")

        except Exception as e:
            QMessageBox.critical(self, "Connection Error", f"Failed to connect: {e}")

    def disconnect_from_network(self):
        try:
            if self.is_connected and self.nickname:
                self.send_quit_message()

            if self.network_receiver:
                self.network_receiver.stop()
                self.network_receiver.wait(3000)
                self.network_receiver = None

            self.is_connected = False
            self.nickname = None
            self.peer_manager.clear()

            self.message_input.setEnabled(False)
            self.send_button.setEnabled(False)
            self.message_input.setPlaceholderText("Type your message... (Connect to network first)")

            self.action_connect.setEnabled(True)
            self.action_disconnect.setEnabled(False)

            self.user_list.clear()
            self.user_list.addItem("📡 Network Status: Disconnected")
            self.chat_display.append("🔌 Disconnected from network")
        except Exception as e:
            QMessageBox.critical(self, "Disconnect Error", f"Failed to disconnect cleanly: {e}")

    def send_message(self):
        if not self.is_connected or not self.nickname:
            return

        message_text = self.message_input.text().strip()
        if not message_text:
            return

        try:
            msg = ChatMessage("chat", self.nickname, message_text)
            
            # DEBUG: Check peer count
            peer_count = len(self.peer_manager.peers)
            print(f"[DEBUG] Sending message to {peer_count} peers")
            self.chat_display.append(f"🔍 DEBUG: Attempting to send to {peer_count} peers")
            
            if peer_count == 0:
                self.chat_display.append("⚠️ WARNING: No peers available to send message to!")
                print("[DEBUG] No peers in peer_manager.peers!")
                return
            
            # DEBUG: Show all peers
            for peer_id, peer_info in self.peer_manager.peers.items():
                print(f"[DEBUG] Peer {peer_id[:8]}...: {peer_info['nickname']}")
                pubkey_b64 = peer_info["public_key"]
                print(f"[DEBUG] Sending to {peer_info['nickname']}, pubkey length: {len(pubkey_b64)}")
                send_encrypted_message(msg, pubkey_b64)

            timestamp = time.strftime("%H:%M:%S")
            self.chat_display.append(f"[{timestamp}] {self.nickname}: {message_text}")
            self.message_input.clear()

        except Exception as e:
            print(f"[ERROR] Send message failed: {e}")
            QMessageBox.critical(self, "Send Error", f"Failed to send message: {e}")

    def send_join_message(self):
        try:
            public_key_b64 = export_public_key_base64(self.public_key)
            msg = ChatMessage("join", self.nickname, public_key_b64)
            
            print(f"[DEBUG] Sending JOIN message, my pubkey length: {len(public_key_b64)}")
            self.chat_display.append(f"🔍 DEBUG: Sending JOIN with pubkey length {len(public_key_b64)}")

            # JOIN messages are too large for RSA encryption (~604 chars > 245 byte limit)
            # So we always send them as raw broadcasts for peer discovery
            print("[DEBUG] Broadcasting JOIN as raw message (too large for RSA encryption)")
            self.chat_display.append("📡 Broadcasting JOIN message (raw - too large for encryption)")
            send_raw_message(msg)

        except Exception as e:
            print(f"[ERROR] Failed to send join message: {e}")
            self.chat_display.append(f"❌ Join message failed: {e}")

    def send_quit_message(self):
        try:
            msg = ChatMessage("quit", self.nickname, "")
            for peer in self.peer_manager.peers.values():
                send_encrypted_message(msg, peer["public_key"])
        except Exception as e:
            print(f"Failed to send quit message: {e}")

    def on_message_received(self, nickname, message_type, data):
        timestamp = time.strftime("%H:%M:%S")
        
        print(f"[DEBUG] Received {message_type} from {nickname}, data length: {len(data) if data else 0}")

        if message_type == "chat":
            if nickname != self.nickname:
                self.chat_display.append(f"[{timestamp}] {nickname}: {data}")

        elif message_type == "join":
            if nickname != self.nickname:
                print(f"[DEBUG] Processing JOIN from {nickname}, pubkey length: {len(data)}")
                self.chat_display.append(f"[{timestamp}] 👋 {nickname} joined the chat")
                self.chat_display.append(f"🔍 DEBUG: JOIN from {nickname}, pubkey length: {len(data)}")
                
                # Add peer to manager
                old_peer_count = len(self.peer_manager.peers)
                self.peer_manager.add_peer(nickname, data)
                new_peer_count = len(self.peer_manager.peers)
                
                print(f"[DEBUG] Peer count: {old_peer_count} -> {new_peer_count}")
                self.chat_display.append(f"🔍 DEBUG: Peer count: {old_peer_count} -> {new_peer_count}")

                # Update UI
                user_items = [self.user_list.item(i).text() for i in range(self.user_list.count())]
                user_entry = f"👤 {nickname}"
                if user_entry not in user_items:
                    self.user_list.addItem(user_entry)

                # Send my info back as RAW broadcast (JOIN messages are too large for RSA encryption)
                try:
                    my_key_b64 = export_public_key_base64(self.public_key)
                    response_msg = ChatMessage("join", self.nickname, my_key_b64)
                    print(f"[DEBUG] Sending JOIN response to {nickname} as RAW broadcast")
                    self.chat_display.append(f"📡 Broadcasting JOIN response for {nickname}")
                    send_raw_message(response_msg)  # Use raw instead of encrypted
                except Exception as e:
                    print(f"[ERROR] Failed to send JOIN response: {e}")

        elif message_type == "quit":
            if nickname != self.nickname:
                self.chat_display.append(f"[{timestamp}] 👋 {nickname} left the chat")
                self.peer_manager.remove_peer(nickname)
                for i in range(self.user_list.count()):
                    if f"👤 {nickname}" in self.user_list.item(i).text():
                        self.user_list.takeItem(i)
                        break


    def toggle_mode(self):
        self.is_gateway_mode = not self.is_gateway_mode
        mode = "Gateway" if self.is_gateway_mode else "Client"
        QMessageBox.information(self, "Mode Toggle", f"Switched to {mode} mode")
        self.chat_display.append(f"🔄 Switched to {mode} mode")

    def show_about(self):
        QMessageBox.information(self, "About", "Barış Can Sertkaya \n20210702022\nCSE471")

    def show_debug_info(self):
        """Display debug information about current peer status"""
        peer_count = len(self.peer_manager.peers)
        debug_info = f"""
🔍 DEBUG INFORMATION:

Connection Status: {'Connected' if self.is_connected else 'Disconnected'}
Nickname: {self.nickname or 'None'}
Mode: {'Gateway' if self.is_gateway_mode else 'Client'}

Peer Count: {peer_count}
        """
        
        if peer_count > 0:
            debug_info += "\nKnown Peers:\n"
            for peer_id, peer_info in self.peer_manager.peers.items():
                debug_info += f"  - {peer_info['nickname']} (ID: {peer_id[:8]}...)\n"
                debug_info += f"    Public Key Length: {len(peer_info['public_key'])} chars\n"
        else:
            debug_info += "\nNo peers known.\n"
            
        self.chat_display.append(debug_info)
        print(debug_info)

    def closeEvent(self, event):
        if self.is_connected:
            self.disconnect_from_network()
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ChatWindow()
    window.show()
    sys.exit(app.exec())
