# Gateway Relay Functionality - Phase 2 Implementation

## Overview

The gateway relay functionality enables communication between peers across different subnets by creating TCP connections between gateway nodes. This implementation provides the basic infrastructure for inter-subnet message relay.

## Architecture

### Components

1. **Gateway Server** (`gateway_server.py`)
   - Listens on TCP port 42070 for incoming connections from remote gateways
   - Handles message reception and parsing
   - Emits signals when messages are received

2. **Gateway Client** (`gateway_client.py`)
   - Manages outgoing connections to remote gateways
   - Maintains persistent TCP connections
   - Handles message forwarding to remote gateways

3. **Gateway Configuration** (`gateways.txt`)
   - Contains IP addresses of remote gateways
   - One IP per line, comments start with #

### Message Flow

```
Local User → Local Broadcast → Gateway → TCP → Remote Gateway → Remote Broadcast → Remote Users
```

## Configuration

### Gateway List Setup

Edit `gateways.txt` to include IP addresses of other gateways:

```
# Gateway configuration
192.168.1.100
10.0.0.50
172.16.1.200
```

**Note**: Do not include your own IP address in the list.

## Usage

### In the Main Application

1. **Enable Gateway Mode**:
   - Go to `Preferences > Toggle Client/Gateway Mode`
   - Switch to Gateway mode

2. **Connect to Network**:
   - Gateway services will automatically start when connecting
   - Monitor connection status in the user list

3. **Message Forwarding**:
   - All local messages are automatically forwarded to remote gateways
   - Messages from remote gateways are rebroadcast locally

### Testing with Test Script

Test the gateway functionality independently:

```bash
# Test message creation and serialization
python test_gateway.py message

# Test gateway server (in one terminal)
python test_gateway.py server

# Test gateway client (in another terminal) 
python test_gateway.py client

# Test Phase 2 features (loop prevention, TTL, caching)
python test_phase2.py
```

## Message Format

### Gateway Message Structure

Gateway messages wrap chat messages with additional routing information:

```json
{
  "source_gateway": "192.168.1.100",
  "gateway_path": ["192.168.1.100"],
  "hop_count": 1,
  "timestamp": 1234567890,
  "message": {
    "type": "chat",
    "nickname": "User1",
    "msg_id": "uuid-here",
    "timestamp": 1234567890,
    "data": "Hello World!"
  }
}
```

### Message Types Supported

- `chat`: Regular chat messages (encrypted, with TTL)
- `join`: User join notifications (raw broadcast, with TTL)
- `quit`: User quit notifications (encrypted, with TTL)

### TTL (Time To Live) Field

All messages now include a TTL field that:
- Starts at 10 hops by default
- Decrements by 1 at each gateway relay
- Prevents infinite message loops
- Drops messages when TTL reaches 0

## Network Ports

- **Local Broadcast**: UDP port 42069 (existing)
- **Gateway Communication**: TCP port 42070 (new)

## Phase 2 Features ✅

1. **Loop Prevention**: Advanced message path tracking and duplicate detection
2. **TTL Handling**: Time-to-live field with automatic hop count limiting
3. **Message Caching**: Smart duplicate message filtering with automatic cleanup
4. **Enhanced Routing**: Gateway path validation to prevent message loops
5. **Background Cleanup**: Automatic expiration of old message cache entries

## Current Limitations (Phase 2)

1. **Basic Error Handling**: Limited connection recovery mechanisms
2. **No QoS**: No message priority or bandwidth management
3. **Static Configuration**: Manual gateway list management

## Security Considerations

- Gateway-to-gateway communication uses real IP addresses (no spoofing)
- Messages between gateways are sent in plaintext JSON
- Local rebroadcast maintains existing encryption/spoofing mechanisms

## Loop Prevention Mechanisms

### Message ID Caching
- Each message gets a unique UUID that's tracked across the network
- Duplicate message IDs are automatically dropped
- Cache entries expire after 5 minutes (configurable)

### Gateway Path Tracking
- Messages track which gateways have processed them
- Prevents forwarding back to gateways already in the path
- Automatic path validation before forwarding

### TTL Enforcement
- Messages start with TTL=10 (configurable)
- TTL decrements at each gateway hop
- Messages with TTL≤0 are dropped

### Background Cleanup
- Automatic cleanup thread removes expired cache entries
- Runs every minute to prevent memory leaks
- Configurable cache timeout (default: 5 minutes)

## Debugging

Enable debug output by watching the console logs:

- `[GATEWAY-SERVER]`: Server-side operations
- `[GATEWAY-CLIENT]`: Client-side operations  
- `[GATEWAY]`: General gateway operations
- `[CACHE]`: Message cache operations
- `[LOOP-PREVENT]`: Loop prevention actions

## Next Phase Implementation

Phase 2 will add:
- Loop prevention mechanisms
- Message ID caching
- TTL/hop count limiting
- Enhanced error handling and recovery
- Connection health monitoring

## File Structure

```
gateway_server.py      # Gateway server implementation
gateway_client.py      # Gateway client implementation
message_cache.py       # Message cache and loop prevention
gateways.txt          # Gateway configuration file
test_gateway.py       # Basic testing utilities
test_phase2.py        # Phase 2 feature tests
GATEWAY_README.md     # This documentation
```

## Troubleshooting

### Common Issues

1. **No Gateway Connections**:
   - Check `gateways.txt` file exists and contains valid IPs
   - Ensure remote gateways are running and accessible
   - Verify firewall settings allow TCP port 42070

2. **Messages Not Forwarding**:
   - Confirm gateway mode is enabled
   - Check console logs for connection status
   - Verify remote gateways are in gateway mode

3. **Connection Failures**:
   - Check network connectivity between gateways
   - Ensure all gateways use the same TCP port (42070)
   - Verify gateways.txt doesn't include own IP address 