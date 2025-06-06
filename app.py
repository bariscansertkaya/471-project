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
from gateway_server import GatewayServer
from gateway_client import GatewayClient, get_local_ip
from message_cache import get_message_cache


class NetworkReceiver(QThread):
    message_received = pyqtSignal(str, str, str, str)  # nickname, type, data, source

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
                self.message_received.emit(message.nickname, message.type, message.data, "local")
                return
        except Exception as e:
            print(f"[DEBUG] Decryption failed (this is normal for raw messages): {e}")

        # Try raw message
        try:
            print("[DEBUG] Attempting to parse as raw message...")
            message = ChatMessage.from_bytes(raw_data)
            if message:
                print(f"[DEBUG] Successfully parsed raw {message.type} message from {message.nickname}")
                self.message_received.emit(message.nickname, message.type, message.data, "local")
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
        
        # Gateway components
        self.gateway_server = None
        self.gateway_client = None
        self.local_gateway_ip = get_local_ip()
        self.message_cache = get_message_cache()

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
        self.user_list.addItem(f"🌐 Local IP: {self.local_gateway_ip}")
        self.user_list.addItem("🔗 Gateway Status: Disabled")
        self.user_list.addItem("🛡️ Cache: 0 messages")

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

            # Start gateway components if in gateway mode
            if self.is_gateway_mode:
                self.start_gateway_services()

            self.is_connected = True
            self.message_input.setEnabled(True)
            self.send_button.setEnabled(True)
            self.message_input.setPlaceholderText(f"Type your message as {self.nickname}...")

            self.action_connect.setEnabled(False)
            self.action_disconnect.setEnabled(True)

            self.user_list.clear()
            self.user_list.addItem("📡 Network Status: Connected")
            self.user_list.addItem(f"🌐 Local IP: {self.local_gateway_ip}")
            if self.is_gateway_mode:
                self.user_list.addItem("🔗 Gateway Status: Active")
            else:
                self.user_list.addItem("🔗 Gateway Status: Disabled")
            self.user_list.addItem(f"👤 {self.nickname} (Me)")

            self.send_join_message()

            self.chat_display.append(f"🌐 Connected to network as '{self.nickname}'")
            if self.is_gateway_mode:
                self.chat_display.append("🌐 Gateway mode active - relaying messages between subnets")
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

            # Stop gateway services
            self.stop_gateway_services()

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
            self.user_list.addItem(f"🌐 Local IP: {self.local_gateway_ip}")
            self.user_list.addItem("🔗 Gateway Status: Disabled")
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
            
            # Send to local peers
            for peer_id, peer_info in self.peer_manager.peers.items():
                print(f"[DEBUG] Peer {peer_id[:8]}...: {peer_info['nickname']}")
                pubkey_b64 = peer_info["public_key"]
                print(f"[DEBUG] Sending to {peer_info['nickname']}, pubkey length: {len(pubkey_b64)}")
                send_encrypted_message(msg, pubkey_b64)

            # Forward to remote gateways if in gateway mode
            if self.is_gateway_mode and self.gateway_client:
                self.gateway_client.send_message_to_gateways(msg)
                print("[GATEWAY] Message forwarded to remote gateways")

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
            
            # Forward JOIN to remote gateways if in gateway mode
            if self.is_gateway_mode and self.gateway_client:
                self.gateway_client.send_message_to_gateways(msg)
                print("[GATEWAY] JOIN message forwarded to remote gateways")

        except Exception as e:
            print(f"[ERROR] Failed to send join message: {e}")
            self.chat_display.append(f"❌ Join message failed: {e}")

    def send_quit_message(self):
        try:
            msg = ChatMessage("quit", self.nickname, "")
            for peer in self.peer_manager.peers.values():
                send_encrypted_message(msg, peer["public_key"])
                
            # Forward QUIT to remote gateways if in gateway mode
            if self.is_gateway_mode and self.gateway_client:
                self.gateway_client.send_message_to_gateways(msg)
                print("[GATEWAY] QUIT message forwarded to remote gateways")
        except Exception as e:
            print(f"Failed to send quit message: {e}")

    def on_message_received(self, nickname, message_type, data, source="local"):
        timestamp = time.strftime("%H:%M:%S")
        
        print(f"[DEBUG] Received {message_type} from {nickname} via {source}, data length: {len(data) if data else 0}")
        
        # Create message object for processing
        try:
            if source == "local":
                msg = ChatMessage(message_type, nickname, data)
            else:
                # For gateway messages, we need to reconstruct with potential TTL
                msg = ChatMessage(message_type, nickname, data)
                
            # Check for duplicate messages (loop prevention)
            if self.message_cache.is_message_seen(msg.msg_id):
                print(f"[LOOP-PREVENT] Dropping duplicate {message_type} from {nickname} (ID: {msg.msg_id[:8]}...)")
                return
                
            # Add message to cache
            self.message_cache.add_message(msg.msg_id)
            self.update_cache_counter()  # Update UI counter
            
            # Forward to remote gateways if this is a local message and we're in gateway mode
            if source == "local" and self.is_gateway_mode and self.gateway_client:
                # Only forward if the message is not from ourselves to prevent loops
                if nickname != self.nickname:
                    self.gateway_client.send_message_to_gateways(msg)
                    print(f"[GATEWAY] Forwarded {message_type} from {nickname} to remote gateways")
                    
        except Exception as e:
            print(f"[ERROR] Error processing message: {e}")
            # Continue processing even if forwarding fails

        if message_type == "chat":
            if nickname != self.nickname:
                self.chat_display.append(f"[{timestamp}] {nickname}: {data}")

        elif message_type == "join":
            if nickname != self.nickname:
                # Check if we already know this peer by their public key (which is in `data`)
                is_new_peer = not self.peer_manager.peer_exists(data)

                if is_new_peer:
                    print(f"[DEBUG] Processing JOIN from new peer: {nickname}")
                    self.chat_display.append(f"[{timestamp}] 👋 {nickname} joined the chat")
                    
                    # Add the new peer
                    self.peer_manager.add_peer(nickname, data)

                    # Update UI list
                    user_items = [self.user_list.item(i).text() for i in range(self.user_list.count())]
                    user_entry = f"👤 {nickname}"
                    if user_entry not in user_items:
                        self.user_list.addItem(user_entry)

                    # Send my info back as a broadcast so the new peer can discover me
                    try:
                        my_key_b64 = export_public_key_base64(self.public_key)
                        response_msg = ChatMessage("join", self.nickname, my_key_b64)
                        print(f"[DEBUG] Sending JOIN response for {nickname} as broadcast")
                        self.chat_display.append(f"📡 Broadcasting JOIN response for {nickname}")
                        send_raw_message(response_msg)
                    except Exception as e:
                        print(f"[ERROR] Failed to send JOIN response: {e}")
                else:
                    # This is a JOIN from a known peer. Ignore it to prevent a loop.
                    print(f"[DEBUG] Ignoring duplicate JOIN from known peer: {nickname}")
                    # As a safeguard, ensure they're on the UI list in case they were removed by mistake
                    user_items = [self.user_list.item(i).text() for i in range(self.user_list.count())]
                    user_entry = f"👤 {nickname}"
                    if user_entry not in user_items:
                        self.user_list.addItem(user_entry)

        elif message_type == "quit":
            if nickname != self.nickname:
                self.chat_display.append(f"[{timestamp}] 👋 {nickname} left the chat")
                self.peer_manager.remove_peer(nickname)
                for i in range(self.user_list.count()):
                    if f"👤 {nickname}" in self.user_list.item(i).text():
                        self.user_list.takeItem(i)
                        break


    def start_gateway_services(self):
        """Start gateway server and client services"""
        try:
            # Start gateway server
            self.gateway_server = GatewayServer()
            self.gateway_server.message_received.connect(self.on_gateway_message_received)
            self.gateway_server.start_server()
            
            # Start gateway client
            self.gateway_client = GatewayClient(self.local_gateway_ip)
            self.gateway_client.connection_status_changed.connect(self.on_gateway_connection_changed)
            self.gateway_client.start_client()
            
            print(f"[GATEWAY] Services started on IP {self.local_gateway_ip}")
            self.chat_display.append(f"🌐 Gateway services started on {self.local_gateway_ip}")
            
        except Exception as e:
            print(f"[GATEWAY] Failed to start services: {e}")
            self.chat_display.append(f"❌ Gateway services failed: {e}")
            
    def stop_gateway_services(self):
        """Stop gateway server and client services"""
        try:
            if self.gateway_server:
                self.gateway_server.stop_server()
                self.gateway_server = None
                
            if self.gateway_client:
                self.gateway_client.stop_client()
                self.gateway_client = None
                
            print("[GATEWAY] Services stopped")
            
        except Exception as e:
            print(f"[GATEWAY] Error stopping services: {e}")
            
    def on_gateway_message_received(self, nickname, message_type, data, source_gateway):
        """Handle messages received from remote gateways"""
        print(f"[GATEWAY] Received {message_type} from {nickname} via gateway {source_gateway}")
        
        # Process the message as if it came from local network (but mark source as gateway)
        self.on_message_received(nickname, message_type, data, f"gateway:{source_gateway}")
        
        # Rebroadcast locally using the existing broadcast mechanism
        try:
            msg = ChatMessage(message_type, nickname, data)
            
            if message_type == "join":
                # For JOIN messages, use raw broadcast (too large for encryption)
                send_raw_message(msg)
                self.chat_display.append(f"🌐 Relayed JOIN from {nickname} (via {source_gateway})")
            else:
                # For other messages, broadcast to local peers
                for peer in self.peer_manager.peers.values():
                    send_encrypted_message(msg, peer["public_key"])
                self.chat_display.append(f"🌐 Relayed {message_type} from {nickname} (via {source_gateway})")
                
        except Exception as e:
            print(f"[GATEWAY] Error relaying message: {e}")
            
    def on_gateway_connection_changed(self, gateway_ip, connected):
        """Handle gateway connection status changes"""
        status = "Connected" if connected else "Disconnected"
        print(f"[GATEWAY] {status} to/from {gateway_ip}")
        self.chat_display.append(f"🔗 Gateway {gateway_ip}: {status}")
        
    def update_cache_counter(self):
        """Update the cache counter in the UI"""
        if hasattr(self, 'message_cache'):
            cache_stats = self.message_cache.get_cache_stats()
            cache_text = f"🛡️ Cache: {cache_stats['total_messages']} messages"
            
            # Find and update the cache status line
            for i in range(self.user_list.count()):
                item = self.user_list.item(i)
                if "🛡️ Cache:" in item.text():
                    item.setText(cache_text)
                    break

    def toggle_mode(self):
        self.is_gateway_mode = not self.is_gateway_mode
        mode = "Gateway" if self.is_gateway_mode else "Client"
        QMessageBox.information(self, "Mode Toggle", f"Switched to {mode} mode")
        self.chat_display.append(f"🔄 Switched to {mode} mode")
        
        # Update UI to reflect mode change
        if self.is_connected:
            # Update the gateway status in the user list
            for i in range(self.user_list.count()):
                item = self.user_list.item(i)
                if "Gateway Status:" in item.text():
                    if self.is_gateway_mode:
                        item.setText("🔗 Gateway Status: Active")
                    else:
                        item.setText("🔗 Gateway Status: Disabled")
                    break

    def show_about(self):
        QMessageBox.information(self, "About", "Barış Can Sertkaya \n20210702022\nCSE471")

    def show_debug_info(self):
        """Display debug information about current peer status"""
        peer_count = len(self.peer_manager.peers)
        cache_stats = self.message_cache.get_cache_stats()
        
        debug_info = f"""
🔍 DEBUG INFORMATION:

Connection Status: {'Connected' if self.is_connected else 'Disconnected'}
Nickname: {self.nickname or 'None'}
Mode: {'Gateway' if self.is_gateway_mode else 'Client'}
Local IP: {self.local_gateway_ip}

Peer Count: {peer_count}

🛡️ Message Cache:
  - Cached Messages: {cache_stats['total_messages']}
  - Gateway Paths: {cache_stats['total_paths']}
  - Cache Timeout: {cache_stats['cache_timeout']}s
  - Cleanup Running: {cache_stats['running']}
        """
        
        if self.is_gateway_mode and self.gateway_client:
            connected_gateways = self.gateway_client.get_connected_gateways()
            debug_info += f"\n🌐 Gateway Connections: {len(connected_gateways)}\n"
            for gw in connected_gateways:
                debug_info += f"  - {gw}\n"
        
        if peer_count > 0:
            debug_info += "\n👥 Known Peers:\n"
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
