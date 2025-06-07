#!/usr/bin/env python3
"""
Test script to simulate real app usage and debug long message issues.
"""

import sys
import os
from crypto_utils import load_keys, export_public_key_base64
from message import ChatMessage
from packet_sender import send_message_auto, send_large_encrypted_message
from multipart_message import MultipartMessageSender, MultipartMessageAssembler, MessageFragment
import time

def test_real_app_scenario():
    """Test scenario that mimics real app usage."""
    print("=== Testing Real App Scenario ===")
    
    try:
        # Load or generate keys
        if os.path.exists("keys/privkey.pem") and os.path.exists("keys/pubkey.pem"):
            private_key, public_key = load_keys()
            print("✅ Loaded existing keys")
        else:
            print("❌ No keys found. Run the app first to generate keys.")
            return False
        
        public_key_b64 = export_public_key_base64(public_key)
        print(f"Public key length: {len(public_key_b64)} chars")
        
        # Test small message
        print("\n--- Testing Small Message ---")
        small_msg = ChatMessage("chat", "TestUser", "Hello!")
        print(f"Small message size: {len(small_msg.to_json().encode('utf-8'))} bytes")
        send_message_auto(small_msg, public_key_b64)
        
        # Test medium message
        print("\n--- Testing Medium Message ---")
        medium_text = "This is a medium-sized message that should trigger the large message protocol. " * 3
        medium_msg = ChatMessage("chat", "TestUser", medium_text)
        print(f"Medium message size: {len(medium_msg.to_json().encode('utf-8'))} bytes")
        send_message_auto(medium_msg, public_key_b64)
        
        # Test large message
        print("\n--- Testing Large Message ---")
        large_text = "This is a very long message that will definitely need multi-part transmission! " * 50
        large_msg = ChatMessage("chat", "TestUser", large_text)
        print(f"Large message size: {len(large_msg.to_json().encode('utf-8'))} bytes")
        send_message_auto(large_msg, public_key_b64)
        
        print("\n✅ All message sending tests completed")
        return True
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_fragment_creation():
    """Test fragment creation directly."""
    print("\n=== Testing Fragment Creation ===")
    
    try:
        private_key, public_key = load_keys()
        public_key_b64 = export_public_key_base64(public_key)
        
        # Create a large message
        large_text = "Testing fragment creation! " * 100
        large_msg = ChatMessage("chat", "TestUser", large_text)
        message_size = len(large_msg.to_json().encode('utf-8'))
        print(f"Message size: {message_size} bytes")
        
        # Create sender and try to fragment
        sender = MultipartMessageSender(max_fragment_size=400)
        fragments = sender.create_fragments(large_msg, public_key_b64)
        
        print(f"Created {len(fragments)} fragments")
        
        # Test fragment serialization
        for i, fragment in enumerate(fragments):
            fragment_bytes = fragment.to_bytes()
            print(f"Fragment {i+1} size: {len(fragment_bytes)} bytes")
            
            # Test deserialization
            reconstructed = MessageFragment.from_bytes(fragment_bytes)
            if reconstructed:
                print(f"✅ Fragment {i+1} serialization/deserialization works")
            else:
                print(f"❌ Fragment {i+1} deserialization failed")
                return False
        
        print("✅ All fragment operations successful")
        return True
        
    except Exception as e:
        print(f"❌ Fragment test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_assembler():
    """Test message assembler."""
    print("\n=== Testing Message Assembler ===")
    
    try:
        private_key, public_key = load_keys()
        public_key_b64 = export_public_key_base64(public_key)
        
        # Create assembler
        assembler = MultipartMessageAssembler(private_key)
        
        # Create a large message and fragment it
        large_text = "Testing assembler functionality! " * 50
        large_msg = ChatMessage("chat", "TestUser", large_text)
        
        sender = MultipartMessageSender(max_fragment_size=400)
        fragments = sender.create_fragments(large_msg, public_key_b64)
        
        print(f"Created {len(fragments)} fragments for assembly test")
        
        # Send fragments to assembler
        complete_message = None
        for i, fragment in enumerate(fragments):
            print(f"Processing fragment {i+1}/{len(fragments)}")
            complete_message = assembler.add_fragment(fragment)
            if complete_message:
                print("✅ Message assembled!")
                break
        
        if complete_message:
            if complete_message.data == large_msg.data:
                print("✅ Assembled message matches original")
                return True
            else:
                print("❌ Assembled message doesn't match original")
                print(f"Original length: {len(large_msg.data)}")
                print(f"Assembled length: {len(complete_message.data)}")
                return False
        else:
            print("❌ Message not assembled")
            return False
            
    except Exception as e:
        print(f"❌ Assembler test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("🧪 Testing Real Message Scenarios\n")
    
    success = True
    success &= test_fragment_creation()
    success &= test_assembler()
    success &= test_real_app_scenario()
    
    if success:
        print("\n✅ All tests passed!")
    else:
        print("\n❌ Some tests failed!")
        sys.exit(1) 