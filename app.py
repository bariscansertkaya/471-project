from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QTextEdit, QLineEdit, QPushButton,
    QVBoxLayout, QHBoxLayout, QWidget, QListWidget, QMenuBar, QMenu,
    QFileDialog, QMessageBox, QInputDialog
)
from PyQt6.QtGui import QAction
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
import platform
import sys
import os
from crypto_utils import generate_key_pair, load_keys, export_public_key_base64, import_public_key_base64
from message import ChatMessage
from packet_sender import send_encrypted_message
from packet_receiver import INTERFACE, DEST_PORT
from scapy.all import sniff, Raw
import threading
import time


class NetworkReceiver(QThread):
    """Background thread for receiving network packets"""
    message_received = pyqtSignal(str, str, str)  # nickname, message_type, data
    
    def __init__(self, private_key):
        super().__init__()
        self.private_key = private_key
        self.running = False
        
    def handle_packet(self, packet):
        """Handle incoming packets"""
        if not packet.haslayer(Raw):
            return
            
        raw_data = packet[Raw].load
        
        try:
            # Attempt to decrypt the message
            message = ChatMessage.decrypt(raw_data, self.private_key)
            if message:
                self.message_received.emit(message.nickname, message.type, message.data)
        except Exception as e:
            print(f"[!] Error processing packet: {e}")
    
    def run(self):
        """Run the packet sniffer in background thread"""
        self.running = True
        try:
            sniff(iface=INTERFACE, prn=self.handle_packet, filter=f"udp port {DEST_PORT}", 
                  stop_filter=lambda x: not self.running, store=False)
        except Exception as e:
            print(f"[!] Network receiver error: {e}")
    
    def stop(self):
        """Stop the network receiver"""
        self.running = False


class ChatWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Anonymous Chat Network")
        self.resize(800, 600)
        
        # Application state
        self.private_key = None
        self.public_key = None
        self.nickname = None
        self.is_connected = False
        self.is_gateway_mode = False
        self.network_receiver = None
        self.known_peers = {}  # nickname -> public_key_b64
        
        # Initialize UI
        self.init_ui()
        
        # Try to load existing keys on startup
        self.load_existing_keys()
        
    def init_ui(self):
        # Central widget setup
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Chat display area
        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        self.chat_display.append("🔐 Anonymous P2P Chat Network")
        self.chat_display.append("📝 Use File > Generate Keys to create your key pair")
        self.chat_display.append("🌐 Use File > Connect to Network to start chatting")

        # Message input
        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Type your message... (Connect to network first)")
        self.message_input.setEnabled(False)
        self.message_input.returnPressed.connect(self.send_message)

        # Send button
        self.send_button = QPushButton("Send")
        self.send_button.clicked.connect(self.send_message)
        self.send_button.setEnabled(False)

        # User list
        self.user_list = QListWidget()
        self.user_list.addItem("📡 Network Status: Disconnected")

        # Layout setup
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

        # Menu setup
        self.setup_menus()

    def setup_menus(self):
        """Set up the application menus"""
        self.menu_bar = self.menuBar()

        # Force in-window menubar on macOS (prevents macOS from moving menu items)
        if platform.system() == 'Darwin':
            self.menu_bar.setNativeMenuBar(False)

        file_menu = self.menu_bar.addMenu("File")
        preferences_menu = self.menu_bar.addMenu("Preferences")
        help_menu = self.menu_bar.addMenu("Help")

        # File menu actions
        self.action_generate_keys = QAction("Generate Keys", self)
        self.action_generate_keys.triggered.connect(self.generate_keys)

        self.action_connect = QAction("Connect to Network", self)
        self.action_connect.triggered.connect(self.connect_to_network)

        self.action_disconnect = QAction("Disconnect from Network", self)
        self.action_disconnect.triggered.connect(self.disconnect_from_network)
        self.action_disconnect.setEnabled(False)

        self.action_exit = QAction("&Exit", self)
        self.action_exit.triggered.connect(self.close)

        # Preferences menu actions
        self.action_toggle_mode = QAction("Toggle Client/Gateway Mode", self)
        self.action_toggle_mode.triggered.connect(self.toggle_mode)

        # Help menu actions
        self.action_about = QAction("About Developer", self)
        self.action_about.triggered.connect(self.show_about)

        # Add actions to menus
        file_menu.addAction(self.action_generate_keys)
        file_menu.addAction(self.action_connect)
        file_menu.addAction(self.action_disconnect)
        file_menu.addSeparator()
        file_menu.addAction(self.action_exit)

        preferences_menu.addAction(self.action_toggle_mode)
        help_menu.addAction(self.action_about)

    def load_existing_keys(self):
        """Try to load existing keys on startup"""
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
        """Generate new RSA key pair"""
        try:
            self.chat_display.append("🔑 Generating RSA 2048-bit key pair...")
            QApplication.processEvents()  # Update UI
            
            self.private_key, self.public_key = generate_key_pair()
            
            self.chat_display.append("✅ Key pair generated and saved successfully!")
            self.chat_display.append("🔐 Your keys are stored in the 'keys' directory")
            self.action_connect.setEnabled(True)
            
        except Exception as e:
            QMessageBox.critical(self, "Key Generation Error", f"Failed to generate keys: {e}")
            self.chat_display.append(f"❌ Key generation failed: {e}")

    def connect_to_network(self):
        """Connect to the P2P network"""
        if not self.private_key or not self.public_key:
            QMessageBox.warning(self, "No Keys", "Please generate keys first!")
            return
            
        nickname, ok = QInputDialog.getText(self, "Connect to Network", "Enter your nickname:")
        if not ok or not nickname.strip():
            return
            
        self.nickname = nickname.strip()
        
        try:
            # Start network receiver thread
            self.network_receiver = NetworkReceiver(self.private_key)
            self.network_receiver.message_received.connect(self.on_message_received)
            self.network_receiver.start()
            
            # Update UI state
            self.is_connected = True
            self.message_input.setEnabled(True)
            self.send_button.setEnabled(True)
            self.message_input.setPlaceholderText(f"Type your message as {self.nickname}...")
            
            # Update menu states
            self.action_connect.setEnabled(False)
            self.action_disconnect.setEnabled(True)
            
            # Update user list
            self.user_list.clear()
            self.user_list.addItem("📡 Network Status: Connected")
            self.user_list.addItem(f"👤 {self.nickname} (Me)")
            
            # Send join message to announce presence
            self.send_join_message()
            
            self.chat_display.append(f"🌐 Connected to network as '{self.nickname}'")
            self.chat_display.append("💡 You can now send and receive messages!")
            
        except Exception as e:
            QMessageBox.critical(self, "Connection Error", f"Failed to connect: {e}")
            self.chat_display.append(f"❌ Connection failed: {e}")

    def disconnect_from_network(self):
        """Disconnect from the P2P network"""
        try:
            # Send quit message before disconnecting
            if self.is_connected and self.nickname:
                self.send_quit_message()
            
            # Stop network receiver
            if self.network_receiver:
                self.network_receiver.stop()
                self.network_receiver.wait(3000)  # Wait up to 3 seconds
                self.network_receiver = None
            
            # Update UI state
            self.is_connected = False
            self.nickname = None
            self.known_peers.clear()
            
            self.message_input.setEnabled(False)
            self.send_button.setEnabled(False)
            self.message_input.setPlaceholderText("Type your message... (Connect to network first)")
            
            # Update menu states
            self.action_connect.setEnabled(True)
            self.action_disconnect.setEnabled(False)
            
            # Update user list
            self.user_list.clear()
            self.user_list.addItem("📡 Network Status: Disconnected")
            
            self.chat_display.append("🔌 Disconnected from network")
            
        except Exception as e:
            QMessageBox.critical(self, "Disconnect Error", f"Failed to disconnect cleanly: {e}")

    def send_message(self):
        """Send a chat message"""
        if not self.is_connected or not self.nickname:
            return
            
        message_text = self.message_input.text().strip()
        if not message_text:
            return
            
        try:
            # Create and send message
            msg = ChatMessage("chat", self.nickname, message_text)
            
            # For now, broadcast to everyone using our own public key (self-test)
            # In a real implementation, you'd broadcast to all known peer public keys
            our_pubkey_b64 = export_public_key_base64(self.public_key)
            send_encrypted_message(msg, our_pubkey_b64)
            
            # Display in chat (our own message)
            timestamp = time.strftime("%H:%M:%S")
            self.chat_display.append(f"[{timestamp}] {self.nickname}: {message_text}")
            self.message_input.clear()
            
        except Exception as e:
            QMessageBox.critical(self, "Send Error", f"Failed to send message: {e}")
            self.chat_display.append(f"❌ Failed to send message: {e}")

    def send_join_message(self):
        """Send join message to announce presence"""
        try:
            public_key_b64 = export_public_key_base64(self.public_key)
            msg = ChatMessage("join", self.nickname, public_key_b64)
            send_encrypted_message(msg, public_key_b64)  # Broadcast
        except Exception as e:
            print(f"Failed to send join message: {e}")

    def send_quit_message(self):
        """Send quit message to announce departure"""
        try:
            public_key_b64 = export_public_key_base64(self.public_key)
            msg = ChatMessage("quit", self.nickname, "")
            send_encrypted_message(msg, public_key_b64)  # Broadcast
        except Exception as e:
            print(f"Failed to send quit message: {e}")

    def on_message_received(self, nickname, message_type, data):
        """Handle received messages from network thread"""
        timestamp = time.strftime("%H:%M:%S")
        
        if message_type == "chat":
            if nickname != self.nickname:  # Don't show our own messages twice
                self.chat_display.append(f"[{timestamp}] {nickname}: {data}")
        elif message_type == "join":
            if nickname != self.nickname:
                self.chat_display.append(f"[{timestamp}] 👋 {nickname} joined the chat")
                self.known_peers[nickname] = data  # Store public key
                # Add to user list if not already there
                user_items = [self.user_list.item(i).text() for i in range(self.user_list.count())]
                user_entry = f"👤 {nickname}"
                if user_entry not in user_items:
                    self.user_list.addItem(user_entry)
        elif message_type == "quit":
            if nickname != self.nickname:
                self.chat_display.append(f"[{timestamp}] 👋 {nickname} left the chat")
                # Remove from known peers and user list
                self.known_peers.pop(nickname, None)
                for i in range(self.user_list.count()):
                    if f"👤 {nickname}" in self.user_list.item(i).text():
                        self.user_list.takeItem(i)
                        break

    def toggle_mode(self):
        """Toggle between client and gateway mode"""
        self.is_gateway_mode = not self.is_gateway_mode
        mode = "Gateway" if self.is_gateway_mode else "Client"
        QMessageBox.information(self, "Mode Toggle", f"Switched to {mode} mode")
        self.chat_display.append(f"🔄 Switched to {mode} mode")

    def show_about(self):
        """Show developer information"""
        QMessageBox.information(self, "About", "Barış Can Sertkaya \n 20210702022 \n CSE471")

    def closeEvent(self, event):
        """Handle application closing"""
        if self.is_connected:
            self.disconnect_from_network()
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ChatWindow()
    window.show()
    sys.exit(app.exec())
