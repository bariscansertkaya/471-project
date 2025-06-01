# 🧾 Anonymous P2P Chat Network - Task List

## 🚀 Project Setup & Foundation
- [ ] Initialize project structure and dependencies
- [ ] Set up PyQt6 development environment
- [ ] Install required packages (scapy, cryptography, etc.)
- [ ] Create main application entry point

## 🔐 Cryptography Module
- [ ] Implement RSA 2048-bit key pair generation
- [ ] Create key storage and loading functionality
- [ ] Implement message encryption with recipient's public key
- [ ] Implement message decryption with private key
- [ ] Add digital signature creation and verification
- [ ] Create broadcast encryption (encrypt with multiple public keys)
- [ ] Handle base64 encoding/decoding for public keys

## 📦 Packet Structure & Message Handling
- [ ] Define JSON message format structure
- [ ] Implement message types: join, chat, quit
- [ ] Create message ID generation using UUID4
- [ ] Add timestamp handling (Unix epoch)
- [ ] Implement JSON serialization/deserialization
- [ ] Create packet encryption wrapper
- [ ] Implement Raw packet creation for scapy

## 🌐 Network Communication Core
### Local Network (Broadcast)
- [ ] Implement Ethernet layer broadcast using scapy
- [ ] Create IP address spoofing functionality
- [ ] Create MAC address spoofing functionality
- [ ] Implement sendp() packet transmission
- [ ] Create packet reception and filtering

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
- [ ] Create main application window
- [ ] Design chat message display area
- [ ] Implement nickname list sidebar
- [ ] Create message input field
- [ ] Add send button functionality

### Menu System
- [ ] Create File menu
  - [ ] Generate Keys option
  - [ ] Connect to Network (nickname prompt)
  - [ ] Disconnect from Network
  - [ ] Exit application
- [ ] Create Preferences menu
  - [ ] Toggle Client/Gateway Mode
- [ ] Create Help menu
  - [ ] Developer information dialog

### UI Components
- [ ] Design and implement nickname input dialog
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
- [ ] Implement real-time message sending
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
- [ ] Create unit tests for cryptography functions
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
