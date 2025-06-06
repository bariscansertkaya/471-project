#!/usr/bin/env python3
"""
Test script for Phase 2 Gateway functionality - Loop Prevention and TTL
"""

import time
import sys
from message import ChatMessage
from message_cache import MessageCache, get_message_cache
from gateway_server import create_gateway_message
from gateway_client import GatewayClient


def test_message_cache():
    """Test message cache functionality"""
    print("=== Testing Message Cache ===")
    
    cache = MessageCache(cache_timeout=10)  # 10 second timeout for testing
    
    # Test basic caching
    msg1 = ChatMessage("chat", "User1", "Hello World!")
    print(f"Message 1 ID: {msg1.msg_id}")
    
    # First add should succeed
    result1 = cache.add_message(msg1.msg_id, ["192.168.1.1"])
    print(f"First add result: {result1}")
    assert result1 == True, "First add should succeed"
    
    # Second add should fail (duplicate)
    result2 = cache.add_message(msg1.msg_id, ["192.168.1.2"])
    print(f"Second add result: {result2}")
    assert result2 == False, "Second add should fail (duplicate)"
    
    # Test seen check
    is_seen = cache.is_message_seen(msg1.msg_id)
    print(f"Message seen check: {is_seen}")
    assert is_seen == True, "Message should be seen"
    
    # Test gateway path checking
    should_forward1 = cache.should_forward_to_gateway(msg1.msg_id, "192.168.1.1")
    should_forward2 = cache.should_forward_to_gateway(msg1.msg_id, "192.168.1.3")
    print(f"Should forward to 192.168.1.1: {should_forward1}")  # False (in path)
    print(f"Should forward to 192.168.1.3: {should_forward2}")  # True (not in path)
    
    # Test cache stats
    stats = cache.get_cache_stats()
    print(f"Cache stats: {stats}")
    
    print("✅ Message cache tests passed!")


def test_ttl_handling():
    """Test TTL (Time To Live) functionality"""
    print("\n=== Testing TTL Handling ===")
    
    # Create message with TTL
    msg = ChatMessage("chat", "User1", "Hello with TTL", ttl=3)
    print(f"Initial TTL: {msg.ttl}")
    
    # Test TTL decrement
    can_continue = msg.decrement_ttl()
    print(f"After decrement: TTL={msg.ttl}, can_continue={can_continue}")
    assert msg.ttl == 2 and can_continue == True
    
    # Test copy with decremented TTL
    msg_copy = msg.copy_with_decremented_ttl()
    print(f"Original TTL: {msg.ttl}, Copy TTL: {msg_copy.ttl}")
    assert msg.ttl == 2 and msg_copy.ttl == 1
    
    # Test expiration
    msg_expired = ChatMessage("chat", "User1", "Expired", ttl=0)
    is_expired = msg_expired.is_expired()
    print(f"Expired message check: {is_expired}")
    assert is_expired == True
    
    # Decrement to expiration
    while msg.ttl > 0:
        msg.decrement_ttl()
    
    print(f"Final TTL: {msg.ttl}, is_expired: {msg.is_expired()}")
    assert msg.is_expired() == True
    
    print("✅ TTL handling tests passed!")


def test_loop_prevention():
    """Test loop prevention mechanisms"""
    print("\n=== Testing Loop Prevention ===")
    
    cache = MessageCache()
    cache.start_cleanup_thread()
    
    # Simulate a message traveling through gateways
    msg = ChatMessage("chat", "User1", "Loop test message")
    print(f"Testing message: {msg.msg_id[:8]}...")
    
    # Gateway A receives and caches the message
    gateway_a = "192.168.1.100"
    result = cache.add_message(msg.msg_id, [gateway_a])
    print(f"Gateway A add result: {result}")
    assert result == True
    
    # Gateway B should not forward back to Gateway A
    should_forward_to_a = cache.should_forward_to_gateway(msg.msg_id, gateway_a)
    print(f"Should forward back to Gateway A: {should_forward_to_a}")
    assert should_forward_to_a == False
    
    # Gateway B can forward to Gateway C
    gateway_c = "192.168.1.200"
    should_forward_to_c = cache.should_forward_to_gateway(msg.msg_id, gateway_c)
    print(f"Should forward to Gateway C: {should_forward_to_c}")
    assert should_forward_to_c == True
    
    # Add Gateway C to path
    cache.add_gateway_to_path(msg.msg_id, gateway_c)
    
    # Now Gateway C should not receive the message again
    should_forward_to_c_again = cache.should_forward_to_gateway(msg.msg_id, gateway_c)
    print(f"Should forward to Gateway C again: {should_forward_to_c_again}")
    assert should_forward_to_c_again == False
    
    # Test duplicate message detection
    duplicate_result = cache.add_message(msg.msg_id, ["192.168.1.300"])
    print(f"Duplicate message add result: {duplicate_result}")
    assert duplicate_result == False
    
    cache.stop_cleanup_thread()
    print("✅ Loop prevention tests passed!")


def test_cache_cleanup():
    """Test cache cleanup functionality"""
    print("\n=== Testing Cache Cleanup ===")
    
    # Create cache with short timeout
    cache = MessageCache(cache_timeout=2)  # 2 seconds
    
    # Add some messages
    msg1 = ChatMessage("chat", "User1", "Message 1")
    msg2 = ChatMessage("chat", "User2", "Message 2")
    
    cache.add_message(msg1.msg_id)
    cache.add_message(msg2.msg_id)
    
    print(f"Added 2 messages, cache size: {cache.get_cache_stats()['total_messages']}")
    
    # Wait for expiration
    print("Waiting 3 seconds for messages to expire...")
    time.sleep(3)
    
    # Manually trigger cleanup
    cleaned = cache.cleanup_expired_messages()
    print(f"Cleaned up {cleaned} messages")
    
    final_stats = cache.get_cache_stats()
    print(f"Final cache size: {final_stats['total_messages']}")
    
    print("✅ Cache cleanup tests passed!")


def test_enhanced_gateway_message():
    """Test enhanced gateway message with TTL and path tracking"""
    print("\n=== Testing Enhanced Gateway Messages ===")
    
    # Create a message with TTL
    chat_msg = ChatMessage("chat", "TestUser", "Hello Gateway!", ttl=5)
    print(f"Original message TTL: {chat_msg.ttl}")
    
    # Create enhanced gateway message
    gateway_msg = create_gateway_message(
        chat_message=chat_msg,
        source_gateway="192.168.1.100",
        gateway_path=["192.168.1.100"],
        hop_count=1
    )
    
    print("Gateway message structure:")
    for key, value in gateway_msg.items():
        if key == 'message':
            print(f"  {key}:")
            for msg_key, msg_value in value.items():
                print(f"    {msg_key}: {msg_value}")
        else:
            print(f"  {key}: {value}")
    
    # Verify TTL is preserved
    embedded_ttl = gateway_msg['message']['ttl']
    print(f"Embedded TTL: {embedded_ttl}")
    assert embedded_ttl == chat_msg.ttl
    
    print("✅ Enhanced gateway message tests passed!")


def test_global_cache():
    """Test global cache instance"""
    print("\n=== Testing Global Cache Instance ===")
    
    cache1 = get_message_cache()
    cache2 = get_message_cache()
    
    # Should be the same instance
    assert cache1 is cache2, "Global cache should return same instance"
    print("✅ Global cache instance test passed!")


def main():
    """Run all Phase 2 tests"""
    print("🚀 Phase 2 Gateway Functionality Tests")
    print("=" * 50)
    
    try:
        test_message_cache()
        test_ttl_handling() 
        test_loop_prevention()
        test_cache_cleanup()
        test_enhanced_gateway_message()
        test_global_cache()
        
        print("\n" + "=" * 50)
        print("🎉 All Phase 2 tests passed successfully!")
        
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