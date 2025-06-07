#!/usr/bin/env python3
"""
Test script for multi-part message system.
Tests both small and large message encryption/decryption.
"""

import time
from crypto_utils import generate_key_pair, export_public_key_base64
from message import ChatMessage
from multipart_message import MultipartMessageSender, MultipartMessageAssembler, MessageFragment
from packet_sender import send_message_auto

def test_small_message():
    """Test small message handling."""
    print("=== Testing Small Message ===")
    
    # Generate key pair
    private_key, public_key = generate_key_pair()
    public_key_b64 = export_public_key_base64(public_key)
    
    # Create small message
    small_msg = ChatMessage("chat", "TestUser", "Hello, this is a small test message!")
    print(f"Original message size: {len(small_msg.to_json().encode('utf-8'))} bytes")
    
    # Test traditional RSA encryption for small messages
    encrypted_bytes = small_msg.encrypt(public_key)
    decrypted_msg = ChatMessage.decrypt(encrypted_bytes, private_key)
    
    print(f"Original: {small_msg.data}")
    print(f"Decrypted: {decrypted_msg.data}")
    print(f"Success: {small_msg.data == decrypted_msg.data}")
    print()

def test_large_message():
    """Test large message multi-part handling."""
    print("=== Testing Large Message ===")
    
    # Generate key pair
    private_key, public_key = generate_key_pair()
    public_key_b64 = export_public_key_base64(public_key)
    
    # Create large message
    large_text = "This is a very long message that will need to be split into multiple parts! " * 50
    large_msg = ChatMessage("chat", "TestUser", large_text)
    print(f"Original message size: {len(large_msg.to_json().encode('utf-8'))} bytes")
    
    # Create multipart sender and assembler
    sender = MultipartMessageSender(max_fragment_size=400)
    assembler = MultipartMessageAssembler(private_key)
    
    # Split message into fragments
    fragments = sender.create_fragments(large_msg, public_key_b64)
    print(f"Message split into {len(fragments)} fragments")
    
    # Simulate sending/receiving fragments
    complete_message = None
    for i, fragment in enumerate(fragments):
        print(f"Processing fragment {i + 1}/{len(fragments)}")
        
        # Simulate network transmission by converting to bytes and back
        fragment_bytes = fragment.to_bytes()
        received_fragment = MessageFragment.from_bytes(fragment_bytes)
        
        if received_fragment:
            complete_message = assembler.add_fragment(received_fragment)
            if complete_message:
                print("Message assembly complete!")
                break
    
    if complete_message:
        print(f"Original: {large_msg.data[:100]}...")
        print(f"Reconstructed: {complete_message.data[:100]}...")
        print(f"Success: {large_msg.data == complete_message.data}")
        print(f"Lengths match: {len(large_msg.data)} == {len(complete_message.data)}")
    else:
        print("❌ Failed to reconstruct message")
    print()

def test_out_of_order_fragments():
    """Test handling fragments received out of order."""
    print("=== Testing Out-of-Order Fragments ===")
    
    # Generate key pair
    private_key, public_key = generate_key_pair()
    public_key_b64 = export_public_key_base64(public_key)
    
    # Create large message
    large_text = "Testing out-of-order fragment delivery! " * 30
    large_msg = ChatMessage("chat", "TestUser", large_text)
    print(f"Original message size: {len(large_msg.to_json().encode('utf-8'))} bytes")
    
    # Create multipart sender and assembler
    sender = MultipartMessageSender(max_fragment_size=400)
    assembler = MultipartMessageAssembler(private_key)
    
    # Split message into fragments
    fragments = sender.create_fragments(large_msg, public_key_b64)
    print(f"Message split into {len(fragments)} fragments")
    
    # Shuffle fragments to simulate out-of-order delivery
    import random
    shuffled_fragments = fragments.copy()
    random.shuffle(shuffled_fragments)
    
    print("Delivering fragments in random order...")
    complete_message = None
    for i, fragment in enumerate(shuffled_fragments):
        print(f"Processing fragment {fragment.fragment_id + 1} (delivery order: {i + 1})")
        
        # Simulate network transmission
        fragment_bytes = fragment.to_bytes()
        received_fragment = MessageFragment.from_bytes(fragment_bytes)
        
        if received_fragment:
            complete_message = assembler.add_fragment(received_fragment)
            if complete_message:
                print("Message assembly complete!")
                break
    
    if complete_message:
        print(f"Success: {large_msg.data == complete_message.data}")
    else:
        print("❌ Failed to reconstruct message")
    print()

def test_missing_fragments():
    """Test handling of missing fragments (timeout)."""
    print("=== Testing Missing Fragment Timeout ===")
    
    # Generate key pair
    private_key, public_key = generate_key_pair()
    public_key_b64 = export_public_key_base64(public_key)
    
    # Create large message
    large_text = "Testing missing fragment handling! " * 20
    large_msg = ChatMessage("chat", "TestUser", large_text)
    
    # Create assembler with short timeout
    assembler = MultipartMessageAssembler(private_key, timeout_seconds=5)
    sender = MultipartMessageSender(max_fragment_size=400)
    
    # Split message into fragments
    fragments = sender.create_fragments(large_msg, public_key_b64)
    print(f"Message split into {len(fragments)} fragments")
    
    # Send only some fragments (simulate packet loss)
    fragments_to_send = fragments[:-1]  # Skip last fragment
    print(f"Sending only {len(fragments_to_send)}/{len(fragments)} fragments")
    
    complete_message = None
    for fragment in fragments_to_send:
        complete_message = assembler.add_fragment(fragment)
        if complete_message:
            break
    
    if complete_message:
        print("❌ Unexpected: Message assembled with missing fragments")
    else:
        print("✅ Expected: Message not assembled due to missing fragments")
    
    # Check assembler status
    status = assembler.get_status()
    print(f"Pending messages: {len(status)}")
    for msg_id, msg_status in status.items():
        print(f"  - {msg_id}: {msg_status['fragments_received']}/{msg_status['total_fragments']} fragments")
    print()

if __name__ == "__main__":
    print("🧪 Testing Multi-part Message System\n")
    
    try:
        test_small_message()
        test_large_message()
        test_out_of_order_fragments()
        test_missing_fragments()
        
        print("✅ All tests completed!")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc() 