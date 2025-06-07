#!/usr/bin/env python3
"""
Comprehensive test suite for Phase 3: Reliability & Error Handling

Tests connection management, error handling, message retry, and recovery mechanisms.
"""

import time
import threading
import unittest
from unittest.mock import Mock, patch, MagicMock
import json
import socket

# Import Phase 3 components
from connection_manager import ConnectionManager, ReliableConnection, ConnectionState
from error_handler import ErrorHandler, ErrorCategory, ErrorSeverity, ErrorEvent
from message_retry import MessageRetrySystem, RetryStatus, RetryableMessage
from gateway_client_v3 import EnhancedGatewayClient
from message import ChatMessage


class TestConnectionManager(unittest.TestCase):
    """Test the connection manager functionality"""
    
    def setUp(self):
        self.conn_mgr = ConnectionManager()
        self.test_gateway = "192.168.1.100"
        
    def tearDown(self):
        self.conn_mgr.stop()
        
    def test_connection_lifecycle(self):
        """Test connection creation, monitoring, and cleanup"""
        print("\n--- Testing Connection Lifecycle ---")
        
        # Start connection manager
        self.conn_mgr.start()
        self.assertTrue(self.conn_mgr.running)
        
        # Add gateway
        self.conn_mgr.add_gateway(self.test_gateway)
        self.assertIn(self.test_gateway, self.conn_mgr.connections)
        
        # Check initial state
        connection = self.conn_mgr.connections[self.test_gateway]
        self.assertEqual(connection.state, ConnectionState.DISCONNECTED)
        
        # Remove gateway
        self.conn_mgr.remove_gateway(self.test_gateway)
        self.assertNotIn(self.test_gateway, self.conn_mgr.connections)
        
        print("✓ Connection lifecycle test passed")
        
    def test_reliable_connection(self):
        """Test individual reliable connection"""
        print("\n--- Testing Reliable Connection ---")
        
        conn = ReliableConnection(self.test_gateway)
        
        # Test configuration
        self.assertEqual(conn.gateway_ip, self.test_gateway)
        self.assertEqual(conn.state, ConnectionState.DISCONNECTED)
        self.assertEqual(conn.max_retries, 3)
        
        # Test state changes
        conn._set_state(ConnectionState.CONNECTING)
        self.assertEqual(conn.state, ConnectionState.CONNECTING)
        
        conn._set_state(ConnectionState.CONNECTED)
        self.assertEqual(conn.state, ConnectionState.CONNECTED)
        
        # Test statistics
        stats = conn.get_stats()
        self.assertEqual(stats.current_state, ConnectionState.CONNECTED)
        
        conn.stop()
        print("✓ Reliable connection test passed")
        
    def test_connection_statistics(self):
        """Test connection statistics tracking"""
        print("\n--- Testing Connection Statistics ---")
        
        self.conn_mgr.start()
        self.conn_mgr.add_gateway(self.test_gateway)
        
        # Get statistics
        stats = self.conn_mgr.get_connection_stats()
        self.assertIn(self.test_gateway, stats)
        
        gateway_stats = stats[self.test_gateway]
        self.assertEqual(gateway_stats.total_connects, 0)
        self.assertEqual(gateway_stats.current_state, ConnectionState.DISCONNECTED)
        
        print("✓ Connection statistics test passed")


class TestErrorHandler(unittest.TestCase):
    """Test the error handling system"""
    
    def setUp(self):
        self.error_handler = ErrorHandler("test_errors.log")
        
    def tearDown(self):
        # Clean up test log file
        import os
        try:
            os.remove("logs/test_errors.log")
        except:
            pass
            
    def test_error_creation(self):
        """Test error event creation and logging"""
        print("\n--- Testing Error Creation ---")
        
        error_id = self.error_handler.handle_error(
            ErrorCategory.NETWORK,
            ErrorSeverity.HIGH,
            "test_error",
            "This is a test error",
            context={"test": "data"}
        )
        
        self.assertIsNotNone(error_id)
        self.assertTrue(error_id.startswith("network_test_error_"))
        
        # Check error was stored
        self.assertEqual(len(self.error_handler.errors), 1)
        
        error = self.error_handler.errors[0]
        self.assertEqual(error.category, ErrorCategory.NETWORK)
        self.assertEqual(error.severity, ErrorSeverity.HIGH)
        self.assertEqual(error.error_code, "test_error")
        self.assertEqual(error.message, "This is a test error")
        self.assertEqual(error.context["test"], "data")
        
        print("✓ Error creation test passed")
        
    def test_error_statistics(self):
        """Test error statistics and tracking"""
        print("\n--- Testing Error Statistics ---")
        
        # Create multiple errors
        for i in range(3):
            self.error_handler.handle_error(
                ErrorCategory.MESSAGE,
                ErrorSeverity.MEDIUM,
                f"test_{i}",
                f"Test error {i}"
            )
            
        # Get statistics
        stats = self.error_handler.get_error_stats()
        
        self.assertEqual(stats["total_errors"], 3)
        self.assertEqual(stats["by_category"]["message"], 3)
        self.assertEqual(stats["by_severity"]["medium"], 3)
        
        print("✓ Error statistics test passed")
        
    def test_error_resolution(self):
        """Test error resolution and recovery"""
        print("\n--- Testing Error Resolution ---")
        
        error_id = self.error_handler.handle_error(
            ErrorCategory.SYSTEM,
            ErrorSeverity.LOW,
            "resolvable_error",
            "This error can be resolved"
        )
        
        # Resolve the error
        success = self.error_handler.resolve_error(error_id, "Fixed manually")
        self.assertTrue(success)
        
        # Check error is marked as resolved
        error = self.error_handler.errors[0]
        self.assertTrue(error.resolved)
        self.assertIsNotNone(error.resolution_time)
        self.assertIn("Manual: Fixed manually", error.recovery_actions)
        
        print("✓ Error resolution test passed")


class TestMessageRetrySystem(unittest.TestCase):
    """Test the message retry system"""
    
    def setUp(self):
        self.retry_system = MessageRetrySystem()
        self.test_message = ChatMessage("test_user", "Test message", "test_key")
        self.test_gateway = "192.168.1.200"
        
    def tearDown(self):
        self.retry_system.stop()
        
    def test_retry_message_lifecycle(self):
        """Test message retry lifecycle"""
        print("\n--- Testing Message Retry Lifecycle ---")
        
        self.retry_system.start()
        
        # Add message for retry
        message_id = self.retry_system.add_message(
            self.test_message,
            self.test_gateway,
            priority=1,
            max_retries=3
        )
        
        self.assertIsNotNone(message_id)
        self.assertTrue(message_id.startswith(self.test_gateway))
        
        # Check message is in queue
        self.assertIn(message_id, self.retry_system.retry_queue)
        
        retryable_msg = self.retry_system.retry_queue[message_id]
        self.assertEqual(retryable_msg.target_gateway, self.test_gateway)
        self.assertEqual(retryable_msg.priority, 1)
        self.assertEqual(retryable_msg.max_retries, 3)
        self.assertEqual(retryable_msg.status, RetryStatus.PENDING)
        
        print("✓ Message retry lifecycle test passed")
        
    def test_retry_delay_calculation(self):
        """Test exponential backoff calculation"""
        print("\n--- Testing Retry Delay Calculation ---")
        
        # Test backoff delays
        delay1 = self.retry_system._calculate_retry_delay(0)
        delay2 = self.retry_system._calculate_retry_delay(1) 
        delay3 = self.retry_system._calculate_retry_delay(2)
        
        # Should increase exponentially
        self.assertGreater(delay2, delay1)
        self.assertGreater(delay3, delay2)
        
        # Should not exceed max delay
        max_delay = self.retry_system._calculate_retry_delay(10)
        self.assertLessEqual(max_delay, self.retry_system.max_retry_delay)
        
        print(f"✓ Retry delays: {delay1:.2f}s, {delay2:.2f}s, {delay3:.2f}s, max: {max_delay:.2f}s")
        
    def test_retry_statistics(self):
        """Test retry system statistics"""
        print("\n--- Testing Retry Statistics ---")
        
        self.retry_system.start()
        
        # Add multiple messages
        for i in range(3):
            self.retry_system.add_message(
                self.test_message,
                f"gateway_{i}",
                priority=i
            )
            
        stats = self.retry_system.get_stats()
        
        self.assertEqual(stats["total_messages"], 3)
        self.assertEqual(stats["current_queue_size"], 3)
        self.assertEqual(stats["queue_status"]["pending"], 3)
        
        print("✓ Retry statistics test passed")
        
    def test_message_cancellation(self):
        """Test message cancellation"""
        print("\n--- Testing Message Cancellation ---")
        
        self.retry_system.start()
        
        message_id = self.retry_system.add_message(
            self.test_message,
            self.test_gateway
        )
        
        # Cancel the message
        success = self.retry_system.cancel_message(message_id)
        self.assertTrue(success)
        
        # Verify message removed
        self.assertNotIn(message_id, self.retry_system.retry_queue)
        
        print("✓ Message cancellation test passed")


class TestEnhancedGatewayClient(unittest.TestCase):
    """Test the enhanced gateway client"""
    
    def setUp(self):
        self.client = EnhancedGatewayClient("127.0.0.1")
        self.test_message = ChatMessage("test_user", "Test message", "test_key")
        
    def tearDown(self):
        if self.client.running:
            self.client.stop_client()
            
    def test_client_initialization(self):
        """Test client initialization and configuration"""
        print("\n--- Testing Client Initialization ---")
        
        self.assertEqual(self.client.local_gateway_ip, "127.0.0.1")
        self.assertFalse(self.client.running)
        self.assertIsNotNone(self.client.connection_manager)
        self.assertIsNotNone(self.client.retry_system)
        self.assertIsNotNone(self.client.message_cache)
        
        print("✓ Client initialization test passed")
        
    def test_gateway_configuration_loading(self):
        """Test loading gateway configuration"""
        print("\n--- Testing Gateway Configuration Loading ---")
        
        # Test with non-existent file
        gateways = self.client.load_gateway_list("nonexistent.txt")
        self.assertEqual(len(gateways), 0)
        
        # Create test configuration file
        with open("test_gateways.txt", "w") as f:
            f.write("192.168.1.10\n")
            f.write("192.168.1.20\n")
            f.write("# Comment line\n")
            f.write("127.0.0.1\n")  # Should be skipped (local IP)
            f.write("\n")  # Empty line
            f.write("192.168.1.30\n")
            
        try:
            gateways = self.client.load_gateway_list("test_gateways.txt")
            self.assertEqual(len(gateways), 3)
            self.assertIn("192.168.1.10", gateways)
            self.assertIn("192.168.1.20", gateways)
            self.assertIn("192.168.1.30", gateways)
            self.assertNotIn("127.0.0.1", gateways)  # Local IP should be excluded
            
        finally:
            import os
            try:
                os.remove("test_gateways.txt")
            except:
                pass
                
        print("✓ Gateway configuration loading test passed")
        
    @patch('socket.socket')
    def test_message_sending_with_mocks(self, mock_socket):
        """Test message sending with mocked connections"""
        print("\n--- Testing Message Sending (Mocked) ---")
        
        # Mock successful socket operations
        mock_sock_instance = Mock()
        mock_socket.return_value = mock_sock_instance
        mock_sock_instance.connect.return_value = None
        mock_sock_instance.send.return_value = None
        
        # Add test gateways
        self.client.gateway_ips = ["192.168.1.10", "192.168.1.20"]
        
        # Test message sending without retry
        results = self.client.send_message_to_gateways(
            self.test_message, 
            use_retry=False
        )
        
        self.assertIsInstance(results, dict)
        print(f"✓ Message sending results: {results}")
        
    def test_statistics_tracking(self):
        """Test statistics tracking"""
        print("\n--- Testing Statistics Tracking ---")
        
        # Get initial statistics
        stats = self.client.get_statistics()
        
        self.assertIn("client_stats", stats)
        self.assertIn("connection_stats", stats)
        self.assertIn("retry_stats", stats)
        self.assertIn("connected_gateways", stats)
        self.assertIn("total_gateways", stats)
        
        client_stats = stats["client_stats"]
        self.assertEqual(client_stats["messages_sent"], 0)
        self.assertEqual(client_stats["messages_failed"], 0)
        
        print("✓ Statistics tracking test passed")


class TestIntegration(unittest.TestCase):
    """Integration tests for Phase 3 components"""
    
    def test_error_handler_integration(self):
        """Test error handler integration with other components"""
        print("\n--- Testing Error Handler Integration ---")
        
        from error_handler import handle_error, get_error_handler
        
        # Test convenience function
        error_id = handle_error(
            ErrorCategory.GATEWAY,
            ErrorSeverity.MEDIUM,
            "integration_test",
            "Integration test error"
        )
        
        self.assertIsNotNone(error_id)
        
        # Check error was recorded
        error_handler = get_error_handler()
        self.assertGreater(len(error_handler.errors), 0)
        
        print("✓ Error handler integration test passed")
        
    def test_system_startup_shutdown(self):
        """Test coordinated startup and shutdown of all systems"""
        print("\n--- Testing System Startup/Shutdown ---")
        
        from connection_manager import get_connection_manager
        from message_retry import get_retry_system
        from error_handler import get_error_handler
        
        # Get global instances
        conn_mgr = get_connection_manager()
        retry_sys = get_retry_system()
        error_handler = get_error_handler()
        
        # Start systems
        conn_mgr.start()
        retry_sys.start()
        
        # Verify running state
        self.assertTrue(conn_mgr.running)
        self.assertTrue(retry_sys.running)
        
        # Stop systems
        retry_sys.stop()
        conn_mgr.stop()
        
        # Verify stopped state
        self.assertFalse(conn_mgr.running)
        self.assertFalse(retry_sys.running)
        
        print("✓ System startup/shutdown test passed")


class TestReliabilityScenarios(unittest.TestCase):
    """Test various reliability scenarios and edge cases"""
    
    def test_connection_failure_recovery(self):
        """Test recovery from connection failures"""
        print("\n--- Testing Connection Failure Recovery ---")
        
        conn_mgr = ConnectionManager()
        conn_mgr.start()
        
        # Add gateway
        test_gateway = "192.168.1.999"  # Non-existent IP
        conn_mgr.add_gateway(test_gateway)
        
        # Let it attempt connection
        time.sleep(2)
        
        # Check that connection is in failed/disconnected state
        stats = conn_mgr.get_connection_stats()
        if test_gateway in stats:
            gateway_stats = stats[test_gateway]
            self.assertIn(gateway_stats.current_state, [
                ConnectionState.DISCONNECTED, 
                ConnectionState.FAILED,
                ConnectionState.CONNECTING
            ])
        
        conn_mgr.stop()
        print("✓ Connection failure recovery test passed")
        
    def test_message_retry_on_failure(self):
        """Test message retry behavior on send failures"""
        print("\n--- Testing Message Retry on Failure ---")
        
        retry_sys = MessageRetrySystem()
        
        # Mock the send method to always fail
        original_send = retry_sys._send_message
        retry_sys._send_message = lambda msg: (False, "Simulated failure")
        
        retry_sys.start()
        
        # Add message that will fail
        test_message = ChatMessage("user", "test", "key")
        message_id = retry_sys.add_message(
            test_message, 
            "192.168.1.999",
            max_retries=2,
            timeout=10
        )
        
        # Wait for retry attempts
        time.sleep(3)
        
        # Check message status
        retryable_msg = retry_sys.get_message_status(message_id)
        if retryable_msg:
            self.assertGreater(retryable_msg.retry_count, 0)
            self.assertGreater(len(retryable_msg.attempts), 0)
        
        # Restore original method
        retry_sys._send_message = original_send
        retry_sys.stop()
        
        print("✓ Message retry on failure test passed")


def run_phase3_tests():
    """Run all Phase 3 tests"""
    print("=" * 60)
    print("PHASE 3 RELIABILITY & ERROR HANDLING TESTS")
    print("=" * 60)
    
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test classes
    test_classes = [
        TestConnectionManager,
        TestErrorHandler, 
        TestMessageRetrySystem,
        TestEnhancedGatewayClient,
        TestIntegration,
        TestReliabilityScenarios
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    print("\n" + "=" * 60)
    print("PHASE 3 TEST SUMMARY")
    print("=" * 60)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.failures:
        print("\nFAILURES:")
        for test, traceback in result.failures:
            print(f"- {test}: {traceback}")
    
    if result.errors:
        print("\nERRORS:")
        for test, traceback in result.errors:
            print(f"- {test}: {traceback}")
    
    success = len(result.failures) == 0 and len(result.errors) == 0
    print(f"\nOVERALL RESULT: {'PASS' if success else 'FAIL'}")
    
    return success


if __name__ == "__main__":
    success = run_phase3_tests()
    exit(0 if success else 1) 