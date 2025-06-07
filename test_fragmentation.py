#!/usr/bin/env python3
"""
Test script for Message Fragmentation System
"""

import time
import sys
import os
from message import ChatMessage
from message_fragmenter import get_message_fragmenter, MessageFragment
from crypto_utils import generate_key_pair, export_public_key_base64


def test_message_fragmentation():
    """Test basic message fragmentation functionality"""
    print("=== Testing Message Fragmentation ===")
    
    fragmenter = get_message_fragmenter()
    
    # Test small message (should not be fragmented)
    small_msg = ChatMessage("chat", "TestUser", "Hello World!")
    needs_frag = fragmenter.needs_fragmentation(small_msg)
    print(f"Small message needs fragmentation: {needs_frag}")
    assert needs_frag == False, "Small message should not need fragmentation"
    
    # Test large message (should be fragmented)
    large_data = "A" * 500  # 500 character message
    large_msg = ChatMessage("chat", "TestUser", large_data)
    needs_frag = fragmenter.needs_fragmentation(large_msg)
    print(f"Large message needs fragmentation: {needs_frag}")
    assert needs_frag == True, "Large message should need fragmentation"
    
    # Fragment the large message
    fragments = fragmenter.fragment_message(large_msg)
    print(f"Large message fragmented into {len(fragments)} parts")
    assert len(fragments) > 1, "Large message should create multiple fragments"
    
    # Verify fragment properties
    for i, fragment in enumerate(fragments):
        print(f"Fragment {i+1}: part_idx={fragment.part_idx}, total_parts={fragment.total_parts}")
        assert fragment.part_idx == i, f"Fragment {i} has wrong part_idx"
        assert fragment.total_parts == len(fragments), f"Fragment {i} has wrong total_parts"
        assert fragment.original_msg_id == large_msg.msg_id, f"Fragment {i} has wrong original_msg_id"
        assert fragment.msg_type == large_msg.type, f"Fragment {i} has wrong msg_type"
        assert fragment.nickname == large_msg.nickname, f"Fragment {i} has wrong nickname"
    
    print("✅ Message fragmentation tests passed!")
    return fragments


def test_fragment_serialization():
    """Test fragment serialization and deserialization"""
    print("\n=== Testing Fragment Serialization ===")
    
    fragmenter = get_message_fragmenter()
    
    # Create a large message and fragment it
    large_data = "B" * 300
    large_msg = ChatMessage("chat", "SerialUser", large_data)
    fragments = fragmenter.fragment_message(large_msg)
    
    # Test serialization/deserialization
    for i, fragment in enumerate(fragments):
        # Convert to ChatMessage
        chat_msg = fragment.to_chat_message()
        print(f"Fragment {i+1} serialized to ChatMessage type: {chat_msg.type}")
        assert chat_msg.type == "fragment", f"Serialized fragment {i} should have type 'fragment'"
        
        # Convert back to MessageFragment
        reconstructed = MessageFragment.from_chat_message(chat_msg)
        assert reconstructed is not None, f"Failed to reconstruct fragment {i}"
        
        # Verify properties
        assert reconstructed.original_msg_id == fragment.original_msg_id, f"Fragment {i} original_msg_id mismatch"
        assert reconstructed.part_idx == fragment.part_idx, f"Fragment {i} part_idx mismatch"
        assert reconstructed.total_parts == fragment.total_parts, f"Fragment {i} total_parts mismatch"
        assert reconstructed.data == fragment.data, f"Fragment {i} data mismatch"
        assert reconstructed.msg_type == fragment.msg_type, f"Fragment {i} msg_type mismatch"
        assert reconstructed.nickname == fragment.nickname, f"Fragment {i} nickname mismatch"
        
        print(f"Fragment {i+1} serialization/deserialization successful")
    
    print("✅ Fragment serialization tests passed!")


def test_message_reassembly():
    """Test message reassembly from fragments"""
    print("\n=== Testing Message Reassembly ===")
    
    fragmenter = get_message_fragmenter()
    
    # Create a large message and fragment it
    original_data = "C" * 400 + "Test message content with special characters: éñüÄß"
    original_msg = ChatMessage("chat", "ReassemblyUser", original_data)
    fragments = fragmenter.fragment_message(original_msg)
    
    print(f"Original message: {len(original_data)} chars")
    print(f"Fragmented into: {len(fragments)} parts")
    
    # Process fragments in order
    complete_msg = None
    for i, fragment in enumerate(fragments):
        print(f"Processing fragment {i+1}/{len(fragments)}")
        complete_msg = fragmenter.process_fragment(fragment)
        
        if i < len(fragments) - 1:
            assert complete_msg is None, f"Message should not be complete until last fragment"
        else:
            assert complete_msg is not None, f"Message should be complete after last fragment"
    
    # Verify reassembled message
    assert complete_msg.msg_id == original_msg.msg_id, "Reassembled message ID mismatch"
    assert complete_msg.type == original_msg.type, "Reassembled message type mismatch"
    assert complete_msg.nickname == original_msg.nickname, "Reassembled message nickname mismatch"
    assert complete_msg.data == original_data, "Reassembled message data mismatch"
    
    print(f"Reassembled message: {len(complete_msg.data)} chars")
    print("✅ Message reassembly tests passed!")


def test_out_of_order_reassembly():
    """Test message reassembly with out-of-order fragments"""
    print("\n=== Testing Out-of-Order Reassembly ===")
    
    fragmenter = get_message_fragmenter()
    
    # Create a large message and fragment it
    original_data = "D" * 600  # Ensure multiple fragments
    original_msg = ChatMessage("chat", "OutOfOrderUser", original_data)
    fragments = fragmenter.fragment_message(original_msg)
    
    # Shuffle fragments to simulate out-of-order arrival
    import random
    shuffled_fragments = fragments.copy()
    random.shuffle(shuffled_fragments)
    
    print(f"Processing {len(fragments)} fragments out of order")
    
    # Process fragments in random order
    complete_msg = None
    for i, fragment in enumerate(shuffled_fragments):
        print(f"Processing fragment {fragment.part_idx + 1}/{fragment.total_parts} (step {i+1})")
        complete_msg = fragmenter.process_fragment(fragment)
        
        if i < len(fragments) - 1:
            assert complete_msg is None, f"Message should not be complete until all fragments received"
    
    # After all fragments processed, should have complete message
    assert complete_msg is not None, "Message should be complete after all fragments"
    assert complete_msg.data == original_data, "Out-of-order reassembled message data mismatch"
    
    print("✅ Out-of-order reassembly tests passed!")


def test_duplicate_fragments():
    """Test handling of duplicate fragments"""
    print("\n=== Testing Duplicate Fragment Handling ===")
    
    fragmenter = get_message_fragmenter()
    
    # Create a large message and fragment it
    original_data = "E" * 350
    original_msg = ChatMessage("chat", "DuplicateUser", original_data)
    fragments = fragmenter.fragment_message(original_msg)
    
    # Process first fragment
    first_fragment = fragments[0]
    result1 = fragmenter.process_fragment(first_fragment)
    assert result1 is None, "First fragment should not complete message"
    
    # Process duplicate of first fragment
    result2 = fragmenter.process_fragment(first_fragment)
    assert result2 is None, "Duplicate fragment should not complete message"
    
    # Process remaining fragments
    complete_msg = None
    for fragment in fragments[1:]:
        complete_msg = fragmenter.process_fragment(fragment)
    
    assert complete_msg is not None, "Message should complete after all unique fragments"
    assert complete_msg.data == original_data, "Message with duplicates should reassemble correctly"
    
    print("✅ Duplicate fragment handling tests passed!")


def test_fragment_expiration():
    """Test partial message expiration"""
    print("\n=== Testing Fragment Expiration ===")
    
    # Create fragmenter with short timeout for testing
    fragmenter = get_message_fragmenter()
    fragmenter.reassembly_timeout = 2.0  # 2 seconds
    
    # Create a large message and fragment it
    original_data = "F" * 300
    original_msg = ChatMessage("chat", "ExpirationUser", original_data)
    fragments = fragmenter.fragment_message(original_msg)
    
    # Process only first fragment
    first_fragment = fragments[0]
    result = fragmenter.process_fragment(first_fragment)
    assert result is None, "First fragment should not complete message"
    
    # Check partial message exists
    stats_before = fragmenter.get_stats()
    assert stats_before['partial_messages'] == 1, "Should have 1 partial message"
    
    # Wait for expiration
    print("Waiting for fragment expiration...")
    time.sleep(3)
    
    # Manually trigger cleanup
    expired_count = fragmenter.cleanup_expired_messages()
    print(f"Cleaned up {expired_count} expired partial messages")
    
    # Check partial message was removed
    stats_after = fragmenter.get_stats()
    assert stats_after['partial_messages'] == 0, "Partial message should be expired and removed"
    
    print("✅ Fragment expiration tests passed!")


def test_large_join_message():
    """Test fragmentation with realistic JOIN message containing public key"""
    print("\n=== Testing Large JOIN Message ===")
    
    fragmenter = get_message_fragmenter()
    
    # Generate a real RSA key pair
    private_key, public_key = generate_key_pair()
    public_key_b64 = export_public_key_base64(public_key)
    
    # Create JOIN message with real public key
    join_msg = ChatMessage("join", "FragmentTestUser", public_key_b64)
    
    message_size = len(join_msg.to_json().encode('utf-8'))
    print(f"JOIN message size: {message_size} bytes")
    print(f"Public key length: {len(public_key_b64)} characters")
    
    # Check if fragmentation is needed
    needs_frag = fragmenter.needs_fragmentation(join_msg)
    print(f"JOIN message needs fragmentation: {needs_frag}")
    
    if needs_frag:
        # Fragment the message
        fragments = fragmenter.fragment_message(join_msg)
        print(f"JOIN message fragmented into {len(fragments)} parts")
        
        # Test reassembly
        complete_msg = None
        for fragment in fragments:
            complete_msg = fragmenter.process_fragment(fragment)
        
        assert complete_msg is not None, "JOIN message should reassemble completely"
        assert complete_msg.type == "join", "Reassembled JOIN message should have correct type"
        assert complete_msg.nickname == "FragmentTestUser", "Reassembled JOIN message should have correct nickname"
        assert complete_msg.data == public_key_b64, "Reassembled JOIN message should have correct public key"
        
        print("JOIN message fragmentation and reassembly successful")
    else:
        print("JOIN message fits in single packet (no fragmentation needed)")
    
    print("✅ Large JOIN message tests passed!")


def test_fragmenter_stats():
    """Test fragmenter statistics functionality"""
    print("\n=== Testing Fragmenter Statistics ===")
    
    fragmenter = get_message_fragmenter()
    
    # Get initial stats
    initial_stats = fragmenter.get_stats()
    print(f"Initial stats: {initial_stats}")
    
    # Create partial message
    large_data = "G" * 400
    large_msg = ChatMessage("chat", "StatsUser", large_data)
    fragments = fragmenter.fragment_message(large_msg)
    
    # Process only some fragments to create partial message
    for fragment in fragments[:-1]:  # Skip last fragment
        fragmenter.process_fragment(fragment)
    
    # Check stats with partial message
    partial_stats = fragmenter.get_stats()
    print(f"Stats with partial message: {partial_stats}")
    assert partial_stats['partial_messages'] == 1, "Should have 1 partial message"
    assert len(partial_stats['partial_details']) == 1, "Should have details for 1 partial message"
    
    # Complete the message
    fragmenter.process_fragment(fragments[-1])
    
    # Check final stats
    final_stats = fragmenter.get_stats()
    print(f"Final stats: {final_stats}")
    assert final_stats['partial_messages'] == 0, "Should have 0 partial messages after completion"
    
    print("✅ Fragmenter statistics tests passed!")


def main():
    """Run all fragmentation tests"""
    print("🚀 Message Fragmentation Test Suite")
    print("=" * 50)
    
    try:
        test_message_fragmentation()
        test_fragment_serialization()
        test_message_reassembly()
        test_out_of_order_reassembly()
        test_duplicate_fragments()
        test_fragment_expiration()
        test_large_join_message()
        test_fragmenter_stats()
        
        print("\n" + "=" * 50)
        print("🎉 All fragmentation tests passed successfully!")
        print("\nKey features verified:")
        print("• ✅ Message fragmentation for large content")
        print("• ✅ Fragment serialization and network transport")
        print("• ✅ Complete message reassembly")
        print("• ✅ Out-of-order fragment handling")
        print("• ✅ Duplicate fragment detection")
        print("• ✅ Partial message expiration and cleanup")
        print("• ✅ Real-world JOIN message handling")
        print("• ✅ Comprehensive statistics and monitoring")
        
        print("\n📦 Message fragmentation system is ready for production!")
        
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        return 1
    except Exception as e:
        print(f"\n💥 Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return 1
        
    return 0


if __name__ == "__main__":
    sys.exit(main()) 