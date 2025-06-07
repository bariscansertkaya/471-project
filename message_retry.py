import time
import threading
import queue
import json
from typing import Dict, Optional, Callable, List
from dataclasses import dataclass, field
from enum import Enum
from message import ChatMessage
from error_handler import handle_error, ErrorCategory, ErrorSeverity


class RetryStatus(Enum):
    PENDING = "pending"
    RETRYING = "retrying"
    SUCCESS = "success"
    FAILED = "failed"
    EXPIRED = "expired"


@dataclass
class RetryAttempt:
    """Represents a single retry attempt"""
    attempt_number: int
    timestamp: float
    error_message: str = ""
    success: bool = False


@dataclass
class RetryableMessage:
    """A message that can be retried with backoff strategy"""
    message: ChatMessage
    target_gateway: str
    retry_count: int = 0
    max_retries: int = 5
    next_retry_time: float = 0
    created_time: float = field(default_factory=time.time)
    status: RetryStatus = RetryStatus.PENDING
    attempts: List[RetryAttempt] = field(default_factory=list)
    priority: int = 0  # Higher = more important
    timeout: float = 300  # 5 minutes default timeout
    
    def __post_init__(self):
        if self.next_retry_time == 0:
            self.next_retry_time = time.time()


class MessageRetrySystem:
    """
    Robust message retry system with exponential backoff, priority queues,
    and intelligent failure handling.
    """
    
    def __init__(self):
        self.retry_queue: Dict[str, RetryableMessage] = {}
        self.processing_queue = queue.PriorityQueue()
        self.lock = threading.RLock()
        self.running = False
        
        # Retry configuration
        self.base_retry_delay = 2.0  # seconds
        self.max_retry_delay = 300.0  # 5 minutes
        self.retry_multiplier = 2.0
        self.jitter_factor = 0.1  # 10% jitter
        
        # Worker threads
        self.worker_threads: List[threading.Thread] = []
        self.num_workers = 3
        
        # Statistics
        self.stats = {
            "total_messages": 0,
            "successful_retries": 0,
            "failed_retries": 0,
            "expired_messages": 0,
            "current_queue_size": 0
        }
        
        # Callbacks
        self.on_message_success: Optional[Callable[[str, RetryableMessage], None]] = None
        self.on_message_failed: Optional[Callable[[str, RetryableMessage], None]] = None
        self.on_message_expired: Optional[Callable[[str, RetryableMessage], None]] = None
    
    def start(self):
        """Start the retry system"""
        with self.lock:
            if self.running:
                return
            
            self.running = True
            
            # Start worker threads
            for i in range(self.num_workers):
                worker = threading.Thread(
                    target=self._worker_loop, 
                    name=f"RetryWorker-{i}",
                    daemon=True
                )
                worker.start()
                self.worker_threads.append(worker)
            
            # Start scheduler thread
            self.scheduler_thread = threading.Thread(
                target=self._scheduler_loop,
                name="RetryScheduler", 
                daemon=True
            )
            self.scheduler_thread.start()
            
            print("[RETRY] Message retry system started")
    
    def stop(self):
        """Stop the retry system"""
        with self.lock:
            self.running = False
            
            # Signal all workers to stop
            for _ in range(self.num_workers):
                self.processing_queue.put((0, time.time(), None))  # Stop signal
        
        # Wait for threads to finish
        for worker in self.worker_threads:
            worker.join(timeout=2)
        
        if hasattr(self, 'scheduler_thread'):
            self.scheduler_thread.join(timeout=2)
        
        print("[RETRY] Message retry system stopped")
    
    def add_message(self, message: ChatMessage, target_gateway: str, 
                   priority: int = 0, max_retries: int = 5, timeout: float = 300) -> str:
        """Add a message to the retry system"""
        with self.lock:
            message_id = f"{target_gateway}_{message.msg_id}_{int(time.time())}"
            
            retryable_msg = RetryableMessage(
                message=message,
                target_gateway=target_gateway,
                max_retries=max_retries,
                priority=priority,
                timeout=timeout
            )
            
            self.retry_queue[message_id] = retryable_msg
            self.stats["total_messages"] += 1
            self.stats["current_queue_size"] = len(self.retry_queue)
            
            # Schedule for immediate processing
            self._schedule_message(message_id, retryable_msg)
            
            print(f"[RETRY] Added message {message_id} for retry (priority: {priority})")
            return message_id
    
    def _schedule_message(self, message_id: str, retryable_msg: RetryableMessage):
        """Schedule a message for processing"""
        # Use negative priority for max-heap behavior (higher priority first)
        priority_score = -retryable_msg.priority
        
        self.processing_queue.put((
            priority_score,
            retryable_msg.next_retry_time,
            message_id
        ))
    
    def _calculate_retry_delay(self, retry_count: int) -> float:
        """Calculate retry delay with exponential backoff and jitter"""
        delay = min(
            self.base_retry_delay * (self.retry_multiplier ** retry_count),
            self.max_retry_delay
        )
        
        # Add jitter to avoid thundering herd
        jitter = delay * self.jitter_factor * (0.5 - time.time() % 1)
        return delay + jitter
    
    def _scheduler_loop(self):
        """Main scheduler loop"""
        while self.running:
            try:
                current_time = time.time()
                
                with self.lock:
                    # Check for expired messages
                    expired_messages = []
                    for message_id, retryable_msg in self.retry_queue.items():
                        if (retryable_msg.status in [RetryStatus.PENDING, RetryStatus.RETRYING] and
                            current_time - retryable_msg.created_time > retryable_msg.timeout):
                            expired_messages.append(message_id)
                    
                    # Handle expired messages
                    for message_id in expired_messages:
                        self._handle_expired_message(message_id)
                
                # Sleep before next check
                time.sleep(5)
                
            except Exception as e:
                handle_error(
                    ErrorCategory.SYSTEM, ErrorSeverity.MEDIUM,
                    "scheduler_error", f"Retry scheduler error: {e}",
                    exception=e
                )
                time.sleep(5)
    
    def _worker_loop(self):
        """Worker thread loop for processing messages"""
        while self.running:
            try:
                # Get next message to process
                priority, scheduled_time, message_id = self.processing_queue.get(timeout=1)
                
                # Check for stop signal
                if message_id is None:
                    break
                
                # Wait until scheduled time
                current_time = time.time()
                if scheduled_time > current_time:
                    time.sleep(scheduled_time - current_time)
                
                # Process the message
                self._process_message(message_id)
                
            except queue.Empty:
                continue
            except Exception as e:
                handle_error(
                    ErrorCategory.SYSTEM, ErrorSeverity.MEDIUM,
                    "worker_error", f"Retry worker error: {e}",
                    exception=e
                )
    
    def _process_message(self, message_id: str):
        """Process a single retry message"""
        with self.lock:
            if message_id not in self.retry_queue:
                return
            
            retryable_msg = self.retry_queue[message_id]
            
            # Check if message has expired
            current_time = time.time()
            if current_time - retryable_msg.created_time > retryable_msg.timeout:
                self._handle_expired_message(message_id)
                return
            
            # Check if max retries exceeded
            if retryable_msg.retry_count >= retryable_msg.max_retries:
                self._handle_failed_message(message_id, "Max retries exceeded")
                return
            
            # Update status
            retryable_msg.status = RetryStatus.RETRYING
            retryable_msg.retry_count += 1
            
            print(f"[RETRY] Processing {message_id} (attempt {retryable_msg.retry_count})")
        
        # Attempt to send message
        success, error_msg = self._send_message(retryable_msg)
        
        with self.lock:
            # Record attempt
            attempt = RetryAttempt(
                attempt_number=retryable_msg.retry_count,
                timestamp=current_time,
                error_message=error_msg,
                success=success
            )
            retryable_msg.attempts.append(attempt)
            
            if success:
                self._handle_successful_message(message_id)
            else:
                # Schedule retry
                delay = self._calculate_retry_delay(retryable_msg.retry_count)
                retryable_msg.next_retry_time = time.time() + delay
                retryable_msg.status = RetryStatus.PENDING
                
                print(f"[RETRY] Message {message_id} failed, retrying in {delay:.1f}s")
                
                # Reschedule
                self._schedule_message(message_id, retryable_msg)
    
    def _send_message(self, retryable_msg: RetryableMessage) -> tuple[bool, str]:
        """Attempt to send message to gateway"""
        try:
            from connection_manager import get_connection_manager
            conn_mgr = get_connection_manager()
            
            # Prepare message data
            message_data = {
                "source_gateway": "local",
                "gateway_path": [],
                "hop_count": 0,
                "timestamp": time.time(),
                "message": retryable_msg.message.to_dict()
            }
            
            # Serialize message
            json_data = json.dumps(message_data).encode('utf-8')
            length_prefix = len(json_data).to_bytes(4, byteorder='big')
            full_data = length_prefix + json_data
            
            # Send to gateway
            success = conn_mgr.send_to_gateway(retryable_msg.target_gateway, full_data)
            
            if success:
                return True, ""
            else:
                return False, "Gateway send failed"
                
        except Exception as e:
            return False, str(e)
    
    def _handle_successful_message(self, message_id: str):
        """Handle successful message delivery"""
        retryable_msg = self.retry_queue[message_id]
        retryable_msg.status = RetryStatus.SUCCESS
        
        self.stats["successful_retries"] += 1
        self.stats["current_queue_size"] = len(self.retry_queue)
        
        print(f"[RETRY] Message {message_id} delivered successfully")
        
        if self.on_message_success:
            try:
                self.on_message_success(message_id, retryable_msg)
            except Exception as e:
                print(f"[RETRY] Error in success callback: {e}")
        
        # Remove from queue after short delay (for stats)
        threading.Timer(10, lambda: self._remove_message(message_id)).start()
    
    def _handle_failed_message(self, message_id: str, reason: str):
        """Handle permanently failed message"""
        retryable_msg = self.retry_queue[message_id]
        retryable_msg.status = RetryStatus.FAILED
        
        self.stats["failed_retries"] += 1
        self.stats["current_queue_size"] = len(self.retry_queue)
        
        print(f"[RETRY] Message {message_id} permanently failed: {reason}")
        
        # Log error
        handle_error(
            ErrorCategory.MESSAGE, ErrorSeverity.HIGH,
            "retry_failed", f"Message retry failed: {reason}",
            context={
                "message_id": message_id,
                "target_gateway": retryable_msg.target_gateway,
                "retry_count": retryable_msg.retry_count
            }
        )
        
        if self.on_message_failed:
            try:
                self.on_message_failed(message_id, retryable_msg)
            except Exception as e:
                print(f"[RETRY] Error in failed callback: {e}")
        
        # Remove from queue after short delay
        threading.Timer(10, lambda: self._remove_message(message_id)).start()
    
    def _handle_expired_message(self, message_id: str):
        """Handle expired message"""
        retryable_msg = self.retry_queue[message_id]
        retryable_msg.status = RetryStatus.EXPIRED
        
        self.stats["expired_messages"] += 1
        self.stats["current_queue_size"] = len(self.retry_queue)
        
        print(f"[RETRY] Message {message_id} expired")
        
        if self.on_message_expired:
            try:
                self.on_message_expired(message_id, retryable_msg)
            except Exception as e:
                print(f"[RETRY] Error in expired callback: {e}")
        
        # Remove from queue
        self._remove_message(message_id)
    
    def _remove_message(self, message_id: str):
        """Remove message from retry queue"""
        with self.lock:
            if message_id in self.retry_queue:
                del self.retry_queue[message_id]
                self.stats["current_queue_size"] = len(self.retry_queue)
    
    def cancel_message(self, message_id: str) -> bool:
        """Cancel a pending retry message"""
        with self.lock:
            if message_id in self.retry_queue:
                retryable_msg = self.retry_queue[message_id]
                if retryable_msg.status in [RetryStatus.PENDING, RetryStatus.RETRYING]:
                    self._remove_message(message_id)
                    print(f"[RETRY] Cancelled message {message_id}")
                    return True
        return False
    
    def get_message_status(self, message_id: str) -> Optional[RetryableMessage]:
        """Get status of a retry message"""
        with self.lock:
            return self.retry_queue.get(message_id)
    
    def get_stats(self) -> Dict:
        """Get retry system statistics"""
        with self.lock:
            stats = self.stats.copy()
            
            # Add current queue breakdown
            queue_status = {}
            for status in RetryStatus:
                queue_status[status.value] = len([
                    msg for msg in self.retry_queue.values() 
                    if msg.status == status
                ])
            
            stats["queue_status"] = queue_status
            stats["queue_size"] = len(self.retry_queue)
            
            return stats
    
    def clear_completed(self):
        """Clear completed/failed messages from queue"""
        with self.lock:
            completed_ids = [
                msg_id for msg_id, msg in self.retry_queue.items()
                if msg.status in [RetryStatus.SUCCESS, RetryStatus.FAILED, RetryStatus.EXPIRED]
            ]
            
            for msg_id in completed_ids:
                del self.retry_queue[msg_id]
            
            self.stats["current_queue_size"] = len(self.retry_queue)
            print(f"[RETRY] Cleared {len(completed_ids)} completed messages")


# Global retry system instance
global_retry_system = MessageRetrySystem()


def get_retry_system() -> MessageRetrySystem:
    """Get the global retry system instance"""
    return global_retry_system


def retry_message(message: ChatMessage, target_gateway: str, 
                 priority: int = 0, max_retries: int = 5, timeout: float = 300) -> str:
    """Convenience function to add message to retry system"""
    return global_retry_system.add_message(
        message, target_gateway, priority, max_retries, timeout
    ) 