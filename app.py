from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QTextEdit, QLineEdit, QPushButton,
    QVBoxLayout, QHBoxLayout, QWidget, QListWidget, QMenuBar, QMenu,
    QFileDialog, QMessageBox, QInputDialog
)
from PyQt6.QtGui import QAction
from PyQt6.QtCore import Qt
import platform
import sys


class ChatWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Anonymous Chat Network")
        self.resize(800, 600)

        # Central widget setup
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Chat display area
        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)

        # Message input
        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Type your message...")

        # Send button
        self.send_button = QPushButton("Send")
        self.send_button.clicked.connect(self.send_message)

        # User list
        self.user_list = QListWidget()
        self.user_list.addItem("Satismaris (Me)")
        self.user_list.addItem("xXx_Fırat_xXx")
        self.user_list.addItem("Rain_falls")

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
        self.menu_bar = self.menuBar()

        # Force in-window menubar on macOS (prevents macOS from moving menu items)
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

        self.action_exit = QAction("&Exit", self)
        self.action_exit.triggered.connect(self.close)

        self.action_toggle_mode = QAction("Toggle Client/Gateway Mode", self)
        self.action_toggle_mode.triggered.connect(self.toggle_mode)

        self.action_about = QAction("About Developer", self)
        self.action_about.triggered.connect(self.show_about)

        file_menu.addAction(self.action_generate_keys)
        file_menu.addAction(self.action_connect)
        file_menu.addAction(self.action_disconnect)
        file_menu.addSeparator()
        file_menu.addAction(self.action_exit)

        preferences_menu.addAction(self.action_toggle_mode)
        help_menu.addAction(self.action_about)

    def send_message(self):
        message = self.message_input.text().strip()
        if message:
            # Encrypt message and send it to the network
            self.chat_display.append(f"Me: {message}")
            self.message_input.clear()

    def generate_keys(self):
        QMessageBox.information(self, "Generate Keys", "Key pair generated successfully (placeholder).")

    def connect_to_network(self):
        nickname, ok = QInputDialog.getText(self, "Connect to Network", "Enter your nickname:")
        if ok and nickname:
            QMessageBox.information(self, "Connect", f"Connected as {nickname} (placeholder).")

    def disconnect_from_network(self):
        QMessageBox.information(self, "Disconnect", "Disconnected from the network (placeholder).")

    def toggle_mode(self):
        QMessageBox.information(self, "Mode Toggle", "Toggled between client and gateway mode (placeholder).")

    def show_about(self):
        QMessageBox.information(self, "About", "Barış Can Sertkaya \n 20210702022 \n CSE471")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ChatWindow()
    window.show()
    sys.exit(app.exec())
