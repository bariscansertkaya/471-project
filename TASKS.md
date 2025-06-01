# 🧾 Anonymous P2P Chat Network - Task List

## 🚀 Project Setup & Foundation
- [X] Initialize project structure and dependencies
- [X] Set up PyQt6 development environment
- [X] Install required packages (scapy, cryptography, etc.)
- [X] Create main application entry point

## 🔐 Cryptography Module
- [X] Implement RSA 2048-bit key pair generation
- [X] Create key storage and loading functionality
- [X] Implement message encryption with recipient's public key
- [X] Implement message decryption with private key
- [ ] Add digital signature creation and verification
- [ ] Create broadcast encryption (encrypt with multiple public keys)
- [X] Handle base64 encoding/decoding for public keys

## 📦 Packet Structure & Message Handling
- [X] Define JSON message format structure
- [X] Implement message types: join, chat, quit
- [X] Create message ID generation using UUID4
- [X] Add timestamp handling (Unix epoch)
- [X] Implement JSON serialization/deserialization
- [X] Create packet encryption wrapper
- [X] Implement Raw packet creation for scapy

## 🌐 Network Communication Core
### Local Network (Broadcast)
- [X] Implement Ethernet layer broadcast using scapy
- [X] Create IP address spoofing functionality
- [X] Create MAC address spoofing functionality
- [X] Implement sendp() packet transmission
- [X] Create packet reception and filtering

### Gateway Mode
- [ ] Implement TCP/UDP socket for inter-subnet communication
- [ ] Create gateway IP list management (gateways.txt)
- [ ] Implement packet relay between local and remote subnets
- [ ] Add gateway discovery and connection logic
- [ ] Create remote gateway message forwarding

## 🌪️ Broadcast Control & Loop Prevention
- [ ] Implement message ID cache with timestamps
- [ ] Create duplicate message detection
- [ ] Add TTL (Time To Live) field handling
- [ ] Implement cache cleanup for expired messages
- [ ] Create loop prevention validation

## 📤 Large Message Handling
- [ ] Implement message splitting into parts
- [ ] Add part_idx and total_parts tracking
- [ ] Create message reassembly logic
- [ ] Handle partial message timeout/cleanup
- [ ] Test large message transmission

## 🧑‍💻 GUI Development (PyQt6)
### Main Window Structure
- [X] Create main application window
- [X] Design chat message display area
- [X] Implement nickname list sidebar
- [X] Create message input field
- [X] Add send button functionality

### Menu System
- [X] Create File menu
  - [X] Generate Keys option
  - [X] Connect to Network (nickname prompt)
  - [X] Disconnect from Network
  - [X] Exit application
- [X] Create Preferences menu
  - [X] Toggle Client/Gateway Mode
- [X] Create Help menu
  - [X] Developer information dialog

### UI Components
- [X] Design and implement nickname input dialog
- [ ] Create key generation progress/status display
- [ ] Implement connection status indicators
- [ ] Add message timestamp display
- [ ] Create user list with online/offline status

## 🛠️ Application Flow Logic
### Startup Flow
- [ ] Implement application launch sequence
- [ ] Create key loading/generation on startup
- [ ] Add mode selection (Client/Gateway)
- [ ] Implement network connection logic
- [ ] Create join message broadcast

### Chat Operations
- [X] Implement real-time message sending
- [ ] Create message reception and display
- [ ] Add user join/quit notifications
- [ ] Implement typing indicators (optional)
- [ ] Create message history storage

### Shutdown Flow
- [ ] Implement graceful disconnect
- [ ] Send quit message broadcast
- [ ] Clean up network resources
- [ ] Save application state

## 🔍 Network Discovery & Peer Management
- [ ] Implement peer discovery from join messages
- [ ] Create peer list management
- [ ] Handle peer timeout/offline detection
- [ ] Add public key storage per peer
- [ ] Implement peer validation

## 🧪 Testing & Validation
- [X] Create unit tests for cryptography functions
- [ ] Test packet spoofing with Wireshark
- [ ] Validate message encryption/decryption
- [ ] Test gateway relay functionality
- [ ] Create multi-instance testing setup
- [ ] Test loop prevention mechanisms
- [ ] Validate large message handling

## 🔧 Configuration & Settings
- [ ] Create application configuration file
- [ ] Implement settings persistence
- [ ] Add gateway list configuration
- [ ] Create logging system
- [ ] Add debug/verbose mode options

## 🌟 Bonus Features (Optional)
- [ ] Implement private chat (direct messaging)
- [ ] Create encrypted file transfer functionality
- [ ] Add file chunking and base64 encoding
- [ ] Implement file transfer progress tracking
- [ ] Create file receive/save functionality

## 🐛 Error Handling & Edge Cases
- [ ] Handle network connection failures
- [ ] Implement packet corruption detection
- [ ] Add timeout handling for operations
- [ ] Create error logging and reporting
- [ ] Handle malformed message validation
- [ ] Add security validation for incoming packets

## 📚 Documentation & Deployment
- [ ] Create user manual/documentation
- [ ] Add code comments and docstrings
- [ ] Create installation instructions
- [ ] Add troubleshooting guide
- [ ] Create demo/example scenarios
