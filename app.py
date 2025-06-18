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
import threading

from crypto_utils import generate_key_pair, load_keys, export_public_key_base64
from message import ChatMessage
from packet_sender import send_encrypted_message, send_raw_message, send_message_auto, send_large_encrypted_message
from packet_receiver import INTERFACE, DEST_PORT, FRAGMENT_PORT, PacketReceiver
from peer_manager import PeerManager


class NetworkReceiver(QThread):
    message_received = pyqtSignal(str, str, str)  # nickname, type, data

    def __init__(self, private_key):
        super().__init__()
        self.private_key = private_key
        self.running = False
        self.packet_receiver = None

    def message_callback(self, nickname, msg_type, data):
        """Callback function for when a complete message is received."""
        self.message_received.emit(nickname, msg_type, data)

    def run(self):
        self.running = True
        try:
            # Use the new PacketReceiver class
            self.packet_receiver = PacketReceiver(self.private_key, self.message_callback)
            self.packet_receiver.start_sniffing()
        except Exception as e:
            print(f"[!] Network receiver error: {e}")

    def stop(self):
        self.running = False
        if self.packet_receiver:
            self.packet_receiver.stop()

    def get_assembler_status(self):
        """Get status of pending multi-part messages."""
        if self.packet_receiver:
            return self.packet_receiver.get_assembler_status()
        return {}


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
        self.peer_manager = PeerManager(peer_timeout_seconds=300, inactive_callback=self.handle_inactive_peer)
        
        # Periodic peer announcement timer
        self.announcement_timer = None

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
            
            # Start periodic peer announcement (every 2 minutes)
            self.start_periodic_announcement()
            
            # Start active peer discovery
            self.start_peer_discovery()

            self.chat_display.append(f"🌐 Connected to network as '{self.nickname}'")
            self.chat_display.append("💡 You can now send and receive messages!")
            self.chat_display.append("🔄 Periodic peer announcements enabled for better discovery")
            self.chat_display.append("🔍 Active peer discovery initiated")

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
                
            # Stop periodic announcements
            self.stop_periodic_announcement()

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
            
            # Check message size and inform user
            message_size = len(msg.to_json().encode('utf-8'))
            if message_size > 180:
                self.chat_display.append(f"📦 Large message detected ({message_size} bytes) - using multi-part encryption")
            
            # DEBUG: Show all peers and send using auto-routing
            successful_sends = 0
            for peer_id, peer_info in self.peer_manager.peers.items():
                print(f"[DEBUG] Peer {peer_id[:8]}...: {peer_info['nickname']}")
                pubkey_b64 = peer_info["public_key"]
                print(f"[DEBUG] Sending to {peer_info['nickname']}, pubkey length: {len(pubkey_b64)}")
                
                # Use auto-routing to choose appropriate sending method
                try:
                    send_message_auto(msg, pubkey_b64)
                    successful_sends += 1
                except Exception as e:
                    print(f"[ERROR] Failed to send to {peer_info['nickname']}: {e}")
                    self.chat_display.append(f"❌ Failed to send to {peer_info['nickname']}: {e}")

            timestamp = time.strftime("%H:%M:%S")
            if successful_sends > 0:
                self.chat_display.append(f"[{timestamp}] {self.nickname}: {message_text}")
                self.chat_display.append(f"📤 Message sent to {successful_sends}/{peer_count} peers")
            else:
                self.chat_display.append(f"❌ Failed to send message to any peers")
            
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

            # JOIN messages are broadcast without encryption for peer discovery
            print("[DEBUG] Broadcasting JOIN message (raw - for peer discovery)")
            self.chat_display.append("📡 Broadcasting JOIN message (raw - for peer discovery)")
            
            # Send JOIN message multiple times with delays to improve reliability
            def send_multiple_joins():
                for i in range(3):  # Send 3 times
                    try:
                        send_message_auto(msg)  # No recipient key = raw broadcast
                        print(f"[DEBUG] JOIN broadcast {i+1}/3 sent successfully")
                        if i < 2:  # Don't sleep after the last one
                            time.sleep(0.2)  # 200ms between broadcasts
                    except Exception as e:
                        print(f"[ERROR] Failed to send JOIN broadcast {i+1}/3: {e}")
                print("[DEBUG] Completed multiple JOIN broadcasts")
            
            # Send in background thread to avoid blocking UI
            join_thread = threading.Thread(target=send_multiple_joins, daemon=True)
            join_thread.start()

        except Exception as e:
            print(f"[ERROR] Failed to send join message: {e}")
            self.chat_display.append(f"❌ Join message failed: {e}")

    def send_quit_message(self):
        try:
            msg = ChatMessage("quit", self.nickname, "")
            peer_count = len(self.peer_manager.peers)
            print(f"[DEBUG] Sending QUIT message to {peer_count} peers")
            self.chat_display.append(f"📤 Sending quit notification to {peer_count} peers...")
            
            successful_quits = 0
            for peer_id, peer_info in self.peer_manager.peers.items():
                try:
                    print(f"[DEBUG] Sending QUIT to {peer_info['nickname']}")
                    send_message_auto(msg, peer_info["public_key"])
                    successful_quits += 1
                except Exception as e:
                    print(f"[ERROR] Failed to send quit to {peer_info['nickname']}: {e}")
            
            print(f"[DEBUG] Successfully sent QUIT to {successful_quits}/{peer_count} peers")
            if successful_quits < peer_count:
                self.chat_display.append(f"⚠️ Quit notification sent to {successful_quits}/{peer_count} peers")
            else:
                self.chat_display.append(f"✅ Quit notification sent to all peers")
                
        except Exception as e:
            print(f"[ERROR] Failed to send quit message: {e}")
            self.chat_display.append(f"❌ Failed to send quit notification: {e}")

    def on_message_received(self, nickname, message_type, data):
        timestamp = time.strftime("%H:%M:%S")
        
        print(f"[DEBUG] Received {message_type} from {nickname}, data length: {len(data) if data else 0}")

        # Skip processing our own messages
        if nickname == self.nickname:
            print(f"[DEBUG] Ignoring message from self: {nickname}")
            return

        # Update peer activity for any message (except our own)
        self.peer_manager.update_peer_activity(nickname)

        # Check if this is an unknown peer (for any message type)
        is_known_peer = any(peer_info["nickname"] == nickname for peer_info in self.peer_manager.peers.values())
        
        if message_type == "chat":
            self.chat_display.append(f"[{timestamp}] {nickname}: {data}")
            
            # If we received a chat message from an unknown peer, request their info
            if not is_known_peer:
                print(f"[DEBUG] Received chat from unknown peer: {nickname}")
                self.chat_display.append(f"[{timestamp}] 🔍 Discovered new peer: {nickname} (requesting peer info)")
                
                # Send a JOIN message to announce ourselves and prompt them to respond
                self.request_peer_info(nickname)

        elif message_type == "join":
            # Check if we already know this peer by their public key (which is in `data`)
            is_new_peer = not self.peer_manager.peer_exists(data)

            if is_new_peer:
                print(f"[DEBUG] Processing JOIN from new peer: {nickname}")
                self.chat_display.append(f"[{timestamp}] 👋 {nickname} joined the chat")
                
                # Add the new peer
                self.peer_manager.add_peer(nickname, data)

                # Update UI list
                self.add_peer_to_ui(nickname)

                # Send my info back as a broadcast so the new peer can discover me
                # Add a small delay to ensure the new peer has time to start listening
                try:
                    my_key_b64 = export_public_key_base64(self.public_key)
                    response_msg = ChatMessage("join", self.nickname, my_key_b64)
                    print(f"[DEBUG] Sending JOIN response for {nickname} as broadcast (with 100ms delay)")
                    self.chat_display.append(f"📡 Broadcasting JOIN response for {nickname} (delayed)")
                    
                    # Small delay to ensure new peer is ready to receive
                    def delayed_response():
                        time.sleep(0.1)  # 100ms delay
                        try:
                            send_message_auto(response_msg)
                            print(f"[DEBUG] JOIN response sent successfully to help {nickname} discover me")
                        except Exception as e:
                            print(f"[ERROR] Failed to send delayed JOIN response: {e}")
                    
                    # Send response in background thread to avoid blocking UI
                    response_thread = threading.Thread(target=delayed_response, daemon=True)
                    response_thread.start()
                    
                except Exception as e:
                    print(f"[ERROR] Failed to prepare JOIN response: {e}")
            else:
                # This is a JOIN from a known peer. Update their info and ensure UI consistency
                print(f"[DEBUG] Received JOIN from known peer: {nickname}, updating info")
                self.peer_manager.add_peer(nickname, data)  # Update their public key and last_seen
                self.add_peer_to_ui(nickname)  # Ensure they're in the UI list

        elif message_type == "quit":
            self.chat_display.append(f"[{timestamp}] 👋 {nickname} left the chat")
            self.handle_peer_disconnect(nickname)

        # For any message from an unknown peer, log the discovery
        if not is_known_peer and message_type != "join":
            print(f"[DEBUG] Message from unknown peer {nickname} - peer discovery may be needed")

    def request_peer_info(self, unknown_peer_nickname):
        """Request peer information from an unknown peer by sending our JOIN message."""
        try:
            print(f"[DEBUG] Requesting peer info from unknown peer: {unknown_peer_nickname}")
            public_key_b64 = export_public_key_base64(self.public_key)
            
            # Send our JOIN message to prompt the unknown peer to respond with theirs
            msg = ChatMessage("join", self.nickname, public_key_b64)
            send_message_auto(msg)  # Raw broadcast
            
            print(f"[DEBUG] Sent peer info request (JOIN broadcast) for {unknown_peer_nickname}")
            self.chat_display.append(f"📡 Sent peer discovery request for {unknown_peer_nickname}")
            
        except Exception as e:
            print(f"[ERROR] Failed to request peer info for {unknown_peer_nickname}: {e}")

    def add_peer_to_ui(self, nickname):
        """Add a peer to the UI list if not already present."""
        user_items = [self.user_list.item(i).text() for i in range(self.user_list.count())]
        user_entry = f"👤 {nickname}"
        
        if user_entry not in user_items:
            self.user_list.addItem(user_entry)
            print(f"[DEBUG] Added {nickname} to UI peer list")
        else:
            print(f"[DEBUG] {nickname} already in UI peer list")

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
                last_seen_ago = int(time.time() - peer_info['last_seen'])
                debug_info += f"  - {peer_info['nickname']} (ID: {peer_id[:8]}...)\n"
                debug_info += f"    Public Key Length: {len(peer_info['public_key'])} chars\n"
                debug_info += f"    Last Seen: {last_seen_ago} seconds ago\n"
        else:
            debug_info += "\nNo peers known.\n"
        
        # Add multi-part message assembler status
        if self.network_receiver and self.is_connected:
            assembler_status = self.network_receiver.get_assembler_status()
            if assembler_status:
                debug_info += "\nPending Multi-part Messages:\n"
                for msg_id, status in assembler_status.items():
                    debug_info += f"  - Message {msg_id}: {status['fragments_received']}/{status['total_fragments']} fragments"
                    debug_info += f" (age: {status['age_seconds']}s)\n"
            else:
                debug_info += "\nNo pending multi-part messages.\n"
        
        # Add peer discovery status
        if self.is_connected:
            debug_info += "\nPeer Discovery Status:\n"
            debug_info += f"  - Periodic Announcements: {'Running' if self.announcement_timer else 'Stopped'}\n"
            debug_info += f"  - Network Interface: {INTERFACE}\n"
            debug_info += f"  - Regular Port: {DEST_PORT}\n"
            debug_info += f"  - Fragment Port: {FRAGMENT_PORT}\n"
        
        self.chat_display.append(debug_info)
        print(debug_info)

    def handle_peer_disconnect(self, nickname):
        """Handle a peer disconnecting (either via quit message or timeout)."""
        print(f"[DEBUG] Handling disconnect for peer: {nickname}")
        
        # Remove from peer manager
        self.peer_manager.remove_peer(nickname)
        
        # Remove from UI list
        for i in range(self.user_list.count()):
            if f"👤 {nickname}" in self.user_list.item(i).text():
                self.user_list.takeItem(i)
                print(f"[DEBUG] Removed {nickname} from UI list")
                break

    def handle_inactive_peer(self, nickname):
        """Handle a peer that has become inactive (timeout)."""
        timestamp = time.strftime("%H:%M:%S")
        print(f"[DEBUG] Peer {nickname} has become inactive")
        self.chat_display.append(f"[{timestamp}] ⏰ {nickname} timed out (inactive)")
        
        # Remove from UI list
        for i in range(self.user_list.count()):
            if f"👤 {nickname}" in self.user_list.item(i).text():
                self.user_list.takeItem(i)
                print(f"[DEBUG] Removed inactive peer {nickname} from UI list")
                break

    def start_periodic_announcement(self):
        """Start periodic announcement of our presence for better peer discovery."""
        def announce_presence():
            if self.is_connected and self.nickname:
                try:
                    print("[DEBUG] Sending periodic peer announcement")
                    public_key_b64 = export_public_key_base64(self.public_key)
                    msg = ChatMessage("join", self.nickname, public_key_b64)
                    send_message_auto(msg)  # Raw broadcast
                    print("[DEBUG] Periodic announcement sent")
                except Exception as e:
                    print(f"[ERROR] Periodic announcement failed: {e}")
        
        def schedule_next():
            if self.is_connected:
                announce_presence()
                # Schedule next announcement in 2 minutes (120 seconds)
                if self.announcement_timer:
                    self.announcement_timer = threading.Timer(120.0, schedule_next)
                    self.announcement_timer.daemon = True
                    self.announcement_timer.start()
        
        # Stop any existing timer
        self.stop_periodic_announcement()
        
        # Start the periodic announcements
        self.announcement_timer = threading.Timer(120.0, schedule_next)  # First announcement in 2 minutes
        self.announcement_timer.daemon = True
        self.announcement_timer.start()
        print("[DEBUG] Periodic peer announcements started (every 2 minutes)")

    def stop_periodic_announcement(self):
        """Stop periodic announcements."""
        if self.announcement_timer:
            self.announcement_timer.cancel()
            self.announcement_timer = None
            print("[DEBUG] Periodic peer announcements stopped")

    def start_peer_discovery(self):
        """Start active peer discovery by sending multiple JOIN messages over time."""
        def discovery_sequence():
            try:
                public_key_b64 = export_public_key_base64(self.public_key)
                
                # Send multiple JOIN messages with increasing delays to catch peers
                # that might have been temporarily unavailable
                discovery_intervals = [0, 5, 15, 30]  # seconds
                
                for i, delay in enumerate(discovery_intervals):
                    if not self.is_connected:
                        break
                        
                    if delay > 0:
                        time.sleep(delay)
                    
                    if self.is_connected:  # Check again after sleep
                        try:
                            msg = ChatMessage("join", self.nickname, public_key_b64)
                            send_message_auto(msg)
                            print(f"[DEBUG] Peer discovery broadcast {i+1}/{len(discovery_intervals)} sent")
                            
                            # Update UI with progress
                            if i == 0:
                                self.chat_display.append("🔍 Starting peer discovery sequence...")
                            elif i == len(discovery_intervals) - 1:
                                self.chat_display.append("✅ Peer discovery sequence completed")
                            
                        except Exception as e:
                            print(f"[ERROR] Peer discovery broadcast {i+1} failed: {e}")
                
                print("[DEBUG] Peer discovery sequence completed")
                
            except Exception as e:
                print(f"[ERROR] Peer discovery sequence failed: {e}")
        
        # Run discovery in background thread
        discovery_thread = threading.Thread(target=discovery_sequence, daemon=True)
        discovery_thread.start()
        print("[DEBUG] Started active peer discovery sequence")

    def closeEvent(self, event):
        if self.is_connected:
            self.disconnect_from_network()
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ChatWindow()
    window.show()
    sys.exit(app.exec())
