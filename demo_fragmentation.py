#!/usr/bin/env python3
"""
Demonstration of Message Fragmentation System
Shows how large messages are automatically fragmented and reassembled
"""

import sys
from crypto_utils import generate_key_pair, export_public_key_base64
from message import ChatMessage
from packet_sender import send_encrypted_message, send_raw_message
from message_fragmenter import get_message_fragmenter


def demo_basic_fragmentation():
    """Demonstrate basic fragmentation concepts"""
    print("🚀 Message Fragmentation Demo")
    print("=" * 50)
    
    # Get fragmenter instance
    fragmenter = get_message_fragmenter()
    
    print(f"📦 Fragmenter settings:")
    print(f"   Max fragment size: {fragmenter.max_fragment_size} bytes")
    print(f"   Reassembly timeout: {fragmenter.reassembly_timeout} seconds")
    print()
    
    # Demo 1: Small message (no fragmentation)
    print("1️⃣ Small Message (No Fragmentation)")
    small_msg = ChatMessage("chat", "DemoUser", "Hello, this is a small message!")
    size = len(small_msg.to_json().encode('utf-8'))
    needs_frag = fragmenter.needs_fragmentation(small_msg)
    
    print(f"   Message: '{small_msg.data}'")
    print(f"   Size: {size} bytes")
    print(f"   Needs fragmentation: {needs_frag}")
    print()
    
    # Demo 2: Large message (requires fragmentation)
    print("2️⃣ Large Message (Requires Fragmentation)")
    large_text = "This is a very long message that will definitely exceed the fragmentation threshold. " * 10
    large_msg = ChatMessage("chat", "DemoUser", large_text)
    size = len(large_msg.to_json().encode('utf-8'))
    needs_frag = fragmenter.needs_fragmentation(large_msg)
    
    print(f"   Message: '{large_text[:50]}...'")
    print(f"   Size: {size} bytes")
    print(f"   Needs fragmentation: {needs_frag}")
    
    if needs_frag:
        fragments = fragmenter.fragment_message(large_msg)
        print(f"   ➤ Fragmented into {len(fragments)} parts")
        
        for i, fragment in enumerate(fragments):
            print(f"     Fragment {i+1}: {len(fragment.data)} bytes")
        print()
    
    # Demo 3: JOIN message with real public key
    print("3️⃣ Real JOIN Message (With RSA Public Key)")
    private_key, public_key = generate_key_pair()
    public_key_b64 = export_public_key_base64(public_key)
    join_msg = ChatMessage("join", "DemoUser", public_key_b64)
    size = len(join_msg.to_json().encode('utf-8'))
    needs_frag = fragmenter.needs_fragmentation(join_msg)
    
    print(f"   Public key length: {len(public_key_b64)} characters")
    print(f"   Total message size: {size} bytes")
    print(f"   Needs fragmentation: {needs_frag}")
    
    if needs_frag:
        fragments = fragmenter.fragment_message(join_msg)
        print(f"   ➤ Fragmented into {len(fragments)} parts")
        
        # Show fragment sizes
        for i, fragment in enumerate(fragments):
            print(f"     Fragment {i+1}: {len(fragment.data)} bytes")
        print()


def demo_reassembly():
    """Demonstrate message reassembly process"""
    print("4️⃣ Message Reassembly Demo")
    print("-" * 30)
    
    fragmenter = get_message_fragmenter()
    
    # Create a large message
    original_data = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. " * 20
    original_msg = ChatMessage("chat", "ReassemblyDemo", original_data)
    
    print(f"   Original message: {len(original_data)} characters")
    
    # Fragment it
    fragments = fragmenter.fragment_message(original_msg)
    print(f"   Created {len(fragments)} fragments")
    
    # Simulate receiving fragments one by one
    print("   Reassembling fragments:")
    complete_msg = None
    for i, fragment in enumerate(fragments):
        complete_msg = fragmenter.process_fragment(fragment)
        if complete_msg:
            print(f"     ✅ Fragment {i+1}/{len(fragments)} - Message complete!")
            break
        else:
            print(f"     📦 Fragment {i+1}/{len(fragments)} - Waiting for more...")
    
    # Verify reassembly
    if complete_msg and complete_msg.data == original_data:
        print("   ✅ Reassembly successful - message matches original!")
    else:
        print("   ❌ Reassembly failed - data mismatch!")
    print()


def demo_out_of_order():
    """Demonstrate out-of-order fragment handling"""
    print("5️⃣ Out-of-Order Fragment Demo")
    print("-" * 30)
    
    fragmenter = get_message_fragmenter()
    
    # Create a large message
    original_data = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" * 50  # Ensure multiple fragments
    original_msg = ChatMessage("chat", "OutOfOrderDemo", original_data)
    
    # Fragment it
    fragments = fragmenter.fragment_message(original_msg)
    print(f"   Created {len(fragments)} fragments")
    
    # Shuffle fragments to simulate out-of-order arrival
    import random
    shuffled = fragments.copy()
    random.shuffle(shuffled)
    
    # Show receiving order
    receive_order = [f.part_idx + 1 for f in shuffled]
    print(f"   Receive order: {receive_order}")
    
    # Process in shuffled order
    print("   Processing out-of-order fragments:")
    complete_msg = None
    for fragment in shuffled:
        complete_msg = fragmenter.process_fragment(fragment)
        if complete_msg:
            print(f"     ✅ Fragment {fragment.part_idx + 1} - Message complete!")
            break
        else:
            print(f"     📦 Fragment {fragment.part_idx + 1} - Partial assembly...")
    
    # Verify reassembly
    if complete_msg and complete_msg.data == original_data:
        print("   ✅ Out-of-order reassembly successful!")
    else:
        print("   ❌ Out-of-order reassembly failed!")
    print()


def demo_network_integration():
    """Demonstrate integration with network sending"""
    print("6️⃣ Network Integration Demo")
    print("-" * 30)
    
    print("   This demo shows how fragmentation integrates with actual sending:")
    print()
    
    # Generate keys for demo
    private_key, public_key = generate_key_pair()
    public_key_b64 = export_public_key_base64(public_key)
    
    # Demo large encrypted message
    large_text = "This is a demonstration of sending a large encrypted message that will be automatically fragmented by the send_encrypted_message function. " * 5
    large_msg = ChatMessage("chat", "NetworkDemo", large_text)
    
    print(f"   Large message size: {len(large_msg.to_json().encode('utf-8'))} bytes")
    print("   📤 Would call: send_encrypted_message(large_msg, recipient_public_key)")
    print("   ➤ System automatically fragments and sends multiple packets")
    print("   ➤ Receiver automatically reassembles complete message")
    print()
    
    # Demo JOIN message
    join_msg = ChatMessage("join", "NetworkDemo", public_key_b64)
    print(f"   JOIN message size: {len(join_msg.to_json().encode('utf-8'))} bytes")
    print("   📤 Would call: send_raw_message(join_msg)")
    print("   ➤ System automatically fragments and sends as raw packets")
    print("   ➤ All peers receive and reassemble the complete JOIN message")
    print()


def demo_statistics():
    """Show fragmenter statistics"""
    print("7️⃣ Fragmenter Statistics")
    print("-" * 30)
    
    fragmenter = get_message_fragmenter()
    stats = fragmenter.get_stats()
    
    print("   Current fragmenter status:")
    for key, value in stats.items():
        if key != 'partial_details':
            print(f"     {key}: {value}")
    
    if stats['partial_details']:
        print("   Partial messages in progress:")
        for msg_id, details in stats['partial_details'].items():
            print(f"     {msg_id}: {details['fragments_received']}/{details['total_expected']} from {details['nickname']}")
    else:
        print("   No partial messages currently in progress")
    print()


def main():
    """Run all demonstrations"""
    try:
        demo_basic_fragmentation()
        demo_reassembly()
        demo_out_of_order()
        demo_network_integration()
        demo_statistics()
        
        print("🎉 Fragmentation Demo Complete!")
        print("\nKey Benefits:")
        print("• ✅ Large messages sent automatically without size limits")
        print("• ✅ Transparent fragmentation - no code changes needed")
        print("• ✅ Robust reassembly handles out-of-order fragments")
        print("• ✅ Automatic cleanup prevents memory leaks")
        print("• ✅ Real-time statistics for monitoring")
        print("• ✅ Works with both encrypted and raw messages")
        
        print("\n📦 Your chat application can now handle messages of any size!")
        
    except Exception as e:
        print(f"\n💥 Demo error: {e}")
        import traceback
        traceback.print_exc()
        return 1
        
    return 0


if __name__ == "__main__":
    sys.exit(main()) 