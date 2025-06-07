#!/usr/bin/env python3
"""
Simplified Phase 3 test suite that doesn't require PyQt6
Tests core reliability features without UI dependencies.
"""

import time
import threading
import sys
import os

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_connection_manager():
    """Test connection manager basic functionality"""
    print("Testing Connection Manager...")
    
    try:
        from connection_manager import ConnectionManager, ConnectionState
        
        conn_mgr = ConnectionManager()
        test_gateway = "192.168.1.100"
        
        # Test initialization
        assert not conn_mgr.running
        assert len(conn_mgr.connections) == 0
        
        # Test adding gateway
        conn_mgr.add_gateway(test_gateway)
        assert test_gateway in conn_mgr.connections
        
        # Test connection state
        connection = conn_mgr.connections[test_gateway]
        assert connection.state == ConnectionState.DISCONNECTED
        
        # Test removal
        conn_mgr.remove_gateway(test_gateway)
        assert test_gateway not in conn_mgr.connections
        
        print("✓ Connection Manager tests passed")
        return True
        
    except Exception as e:
        print(f"✗ Connection Manager test failed: {e}")
        return False


def test_error_handler():
    """Test error handler functionality"""
    print("Testing Error Handler...")
    
    try:
        from error_handler import ErrorHandler, ErrorCategory, ErrorSeverity
        
        error_handler = ErrorHandler("test_errors.log")
        
        # Test error creation
        error_id = error_handler.handle_error(
            ErrorCategory.NETWORK,
            ErrorSeverity.HIGH,
            "test_error",
            "This is a test error",
            context={"test": "data"}
        )
        
        assert error_id is not None
        assert error_id.startswith("network_test_error_")
        assert len(error_handler.errors) == 1
        
        # Test error statistics
        stats = error_handler.get_error_stats()
        assert stats["total_errors"] == 1
        assert stats["by_category"]["network"] == 1
        assert stats["by_severity"]["high"] == 1
        
        print("✓ Error Handler tests passed")
        return True
        
    except Exception as e:
        print(f"✗ Error Handler test failed: {e}")
        return False


def test_message_retry():
    """Test message retry system"""
    print("Testing Message Retry System...")
    
    try:
        from message_retry import MessageRetrySystem, RetryStatus
        from message import ChatMessage
        
        retry_system = MessageRetrySystem()
        test_message = ChatMessage("test_user", "Test message", "test_key")
        test_gateway = "192.168.1.200"
        
        # Test message addition
        message_id = retry_system.add_message(
            test_message,
            test_gateway,
            priority=1,
            max_retries=3
        )
        
        assert message_id is not None
        assert message_id.startswith(test_gateway)
        assert message_id in retry_system.retry_queue
        
        # Test retry delay calculation
        delay1 = retry_system._calculate_retry_delay(0)
        delay2 = retry_system._calculate_retry_delay(1)
        assert delay2 > delay1
        
        # Test statistics
        stats = retry_system.get_stats()
        assert stats["total_messages"] == 1
        assert stats["current_queue_size"] == 1
        
        # Test cancellation
        success = retry_system.cancel_message(message_id)
        assert success
        assert message_id not in retry_system.retry_queue
        
        retry_system.stop()
        
        print("✓ Message Retry System tests passed")
        return True
        
    except Exception as e:
        print(f"✗ Message Retry System test failed: {e}")
        return False


def test_integration():
    """Test integration between components"""
    print("Testing Component Integration...")
    
    try:
        from connection_manager import get_connection_manager
        from error_handler import get_error_handler, handle_error, ErrorCategory, ErrorSeverity
        from message_retry import get_retry_system
        
        # Test global instances
        conn_mgr = get_connection_manager()
        error_handler = get_error_handler()
        retry_sys = get_retry_system()
        
        assert conn_mgr is not None
        assert error_handler is not None
        assert retry_sys is not None
        
        # Test error handling convenience function
        error_id = handle_error(
            ErrorCategory.SYSTEM,
            ErrorSeverity.MEDIUM,
            "integration_test",
            "Integration test error"
        )
        
        assert error_id is not None
        
        # Verify error was recorded
        stats = error_handler.get_error_stats()
        assert stats["total_errors"] > 0
        
        print("✓ Integration tests passed")
        return True
        
    except Exception as e:
        print(f"✗ Integration test failed: {e}")
        return False


def test_reliability_features():
    """Test reliability and recovery features"""
    print("Testing Reliability Features...")
    
    try:
        from connection_manager import ConnectionManager, ConnectionState
        from error_handler import ErrorHandler, ErrorCategory, ErrorSeverity
        
        # Test connection state transitions
        conn_mgr = ConnectionManager()
        test_gateway = "192.168.1.999"  # Non-existent IP
        
        conn_mgr.add_gateway(test_gateway)
        connection = conn_mgr.connections[test_gateway]
        
        # Test state changes
        connection._set_state(ConnectionState.CONNECTING)
        assert connection.state == ConnectionState.CONNECTING
        
        connection._set_state(ConnectionState.FAILED)
        assert connection.state == ConnectionState.FAILED
        
        # Test error recovery registration
        error_handler = ErrorHandler("test_reliability.log")
        
        def test_recovery(error_event):
            return True
            
        error_handler.register_recovery_handler(
            ErrorCategory.NETWORK, 
            "test_error", 
            test_recovery
        )
        
        # Test error with recovery
        error_id = error_handler.handle_error(
            ErrorCategory.NETWORK,
            ErrorSeverity.MEDIUM,
            "test_error",
            "Test error with recovery"
        )
        
        # Check if recovery was attempted
        error = error_handler.errors[-1]
        assert error.resolved
        
        conn_mgr.stop()
        
        print("✓ Reliability features tests passed")
        return True
        
    except Exception as e:
        print(f"✗ Reliability features test failed: {e}")
        return False


def run_simple_tests():
    """Run all simplified Phase 3 tests"""
    print("=" * 60)
    print("PHASE 3 SIMPLIFIED TEST SUITE")
    print("=" * 60)
    
    tests = [
        test_connection_manager,
        test_error_handler,
        test_message_retry,
        test_integration,
        test_reliability_features
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"✗ Test {test.__name__} crashed: {e}")
            failed += 1
        print()
    
    print("=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    print(f"Tests passed: {passed}")
    print(f"Tests failed: {failed}")
    print(f"Total tests: {passed + failed}")
    
    success = failed == 0
    print(f"Overall result: {'PASS' if success else 'FAIL'}")
    
    return success


if __name__ == "__main__":
    success = run_simple_tests()
    sys.exit(0 if success else 1) 