# Gateway Mode Setup Guide

## Testing Between Local Machine and VM

### Step 1: Find IP Addresses

**On Local Machine:**
```bash
# Find your local IP
ifconfig | grep "inet " | grep -v 127.0.0.1
# Or on Windows: ipconfig
# Example output: 192.168.1.100
```

**On VM:**
```bash
# Find VM IP
ifconfig | grep "inet " | grep -v 127.0.0.1
# Example output: 192.168.1.200
```

### Step 2: Configure Gateway Files

**On Local Machine (`gateways.txt`):**
```
# Add VM IP address
192.168.1.200
```

**On VM (`gateways.txt`):**
```
# Add Local machine IP address
192.168.1.100
```

### Step 3: Check Network Connectivity

**Test connection from Local to VM:**
```bash
# Test TCP connection to gateway port
nc -zv 192.168.1.200 42070
# Or use telnet: telnet 192.168.1.200 42070
```

**Test connection from VM to Local:**
```bash
nc -zv 192.168.1.100 42070
```

If these fail, check:
- Firewall settings
- Network configuration
- VM network mode (should be Bridged, not NAT)

### Step 4: Start Applications

**On both machines:**

1. **Generate Keys**: File → Generate Keys
2. **Enable Gateway Mode**: Preferences → Toggle Client/Gateway Mode
3. **Connect**: File → Connect to Network
4. **Check Status**: Look for "Gateway Status: Active" in user list

### Step 5: Verify Gateway Connections

**Look for these logs in terminal:**
```
[GATEWAY-CLIENT] Connected to gateway 192.168.1.xxx
[GATEWAY-SERVER] Gateway server listening on port 42070
[GATEWAY-SERVER] New connection from ('192.168.1.xxx', port)
```

### Step 6: Test Message Flow

1. Send a message from Local machine
2. Should appear on VM 
3. Send a message from VM
4. Should appear on Local machine

## Troubleshooting

### No Gateway Connections

**Check gateways.txt:**
```bash
cat gateways.txt
# Should contain remote IP, not your own IP
```

**Check network interface:**
In `packet_sender.py`, verify `INTERFACE = "en0"` matches your network interface:
```bash
# List network interfaces
ifconfig -a
# Common names: en0, eth0, wlan0, ens33
```

### Messages Not Forwarding

**Check debug output:**
```
[GATEWAY-CLIENT] Message sent to X/Y gateways
[GATEWAY-SERVER] Received message from gateway X.X.X.X
[GATEWAY] Relayed message_type from nickname locally
```

**Verify gateway mode is active:**
- Look for "Gateway Status: Active" in UI
- Check debug info: Help → Show Debug Info

### VM Network Issues

**VM Network Settings:**
- Use **Bridged Adapter** (not NAT)
- Both machines should be on same subnet (192.168.1.x)
- Disable VM firewall for testing

**Firewall Commands:**
```bash
# Ubuntu/Debian - temporarily disable
sudo ufw disable

# CentOS/RHEL - temporarily disable  
sudo systemctl stop firewalld

# macOS - allow incoming on port 42070
# Windows - add firewall exception for port 42070
```

## Expected Behavior

### When Working Correctly:

1. **Connection Logs:**
   ```
   [GATEWAY-CLIENT] Connected to gateway 192.168.1.xxx
   [GATEWAY-SERVER] New connection from ('192.168.1.xxx', port)
   ```

2. **Message Flow:**
   ```
   Local User → [Broadcast] → Gateway → [TCP] → Remote Gateway → [Broadcast] → Remote User
   ```

3. **UI Indicators:**
   - "Gateway Status: Active"
   - "🔗 Gateway 192.168.1.xxx: Connected"
   - Cache counter increases: "🛡️ Cache: X messages"

### Test Scenarios:

1. **Basic Chat**: Messages appear on both machines
2. **Join/Leave**: User joins on one machine, appears on other
3. **Loop Prevention**: No duplicate messages
4. **TTL Working**: Messages don't bounce infinitely

## Quick Test Commands

```bash
# Test message creation
python test_phase2.py

# Test gateway server (on one machine)
python test_gateway.py server

# Test gateway client (on other machine)
python test_gateway.py client
``` 