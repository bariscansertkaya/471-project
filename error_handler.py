import logging
import time
import threading
import traceback
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class ErrorSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"  
    HIGH = "high"
    CRITICAL = "critical"


class ErrorCategory(Enum):
    NETWORK = "network"
    ENCRYPTION = "encryption"
    GATEWAY = "gateway"
    MESSAGE = "message"
    SYSTEM = "system"
    UI = "ui"


@dataclass
class ErrorEvent:
    """Represents an error event with context and recovery information"""
    timestamp: float
    category: ErrorCategory
    severity: ErrorSeverity
    error_code: str
    message: str
    details: str
    context: Dict = field(default_factory=dict)
    stack_trace: Optional[str] = None
    resolved: bool = False
    resolution_time: Optional[float] = None
    recovery_actions: List[str] = field(default_factory=list)


class ErrorHandler:
    """
    Comprehensive error handling system with logging, recovery, and monitoring
    """
    
    def __init__(self, log_file: str = "gateway_errors.log"):
        self.log_file = log_file
        self.errors: List[ErrorEvent] = []
        self.error_counts: Dict[str, int] = {}
        self.lock = threading.RLock()
        
        # Recovery callbacks
        self.recovery_handlers: Dict[str, Callable] = {}
        
        # Error thresholds
        self.error_thresholds = {
            ErrorSeverity.LOW: 10,      # per minute
            ErrorSeverity.MEDIUM: 5,    # per minute  
            ErrorSeverity.HIGH: 3,      # per minute
            ErrorSeverity.CRITICAL: 1   # per minute
        }
        
        # Setup logging
        self._setup_logging()
        
        # Start cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self.cleanup_thread.start()
    
    def _setup_logging(self):
        """Setup logging configuration"""
        # Create logs directory if it doesn't exist
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        # Configure logger
        self.logger = logging.getLogger("GatewayErrorHandler")
        self.logger.setLevel(logging.DEBUG)
        
        # File handler
        file_handler = logging.FileHandler(log_dir / self.log_file)
        file_handler.setLevel(logging.DEBUG)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.WARNING)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # Add handlers
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
    
    def handle_error(self, 
                    category: ErrorCategory,
                    severity: ErrorSeverity,
                    error_code: str,
                    message: str,
                    exception: Optional[Exception] = None,
                    context: Optional[Dict] = None,
                    auto_recover: bool = True) -> str:
        """
        Handle an error event with logging and optional recovery
        
        Returns error ID for tracking
        """
        with self.lock:
            current_time = time.time()
            
            # Create error event
            error_event = ErrorEvent(
                timestamp=current_time,
                category=category,
                severity=severity,
                error_code=error_code,
                message=message,
                details=str(exception) if exception else "",
                context=context or {},
                stack_trace=traceback.format_exc() if exception else None
            )
            
            # Generate error ID
            error_id = f"{category.value}_{error_code}_{int(current_time)}"
            
            # Store error
            self.errors.append(error_event)
            
            # Update error counts
            count_key = f"{category.value}_{severity.value}"
            self.error_counts[count_key] = self.error_counts.get(count_key, 0) + 1
            
            # Log error
            self._log_error(error_event, error_id)
            
            # Check thresholds
            self._check_error_thresholds()
            
            # Attempt auto-recovery
            if auto_recover:
                self._attempt_recovery(error_event, error_id)
            
            return error_id
    
    def _log_error(self, error: ErrorEvent, error_id: str):
        """Log error to file and console"""
        log_message = (
            f"[{error_id}] {error.category.value.upper()} - {error.severity.value.upper()} - "
            f"{error.error_code}: {error.message}"
        )
        
        if error.details:
            log_message += f" | Details: {error.details}"
        
        if error.context:
            log_message += f" | Context: {error.context}"
        
        # Log based on severity
        if error.severity == ErrorSeverity.CRITICAL:
            self.logger.critical(log_message)
        elif error.severity == ErrorSeverity.HIGH:
            self.logger.error(log_message)
        elif error.severity == ErrorSeverity.MEDIUM:
            self.logger.warning(log_message)
        else:
            self.logger.info(log_message)
        
        # Log stack trace if available
        if error.stack_trace:
            self.logger.debug(f"[{error_id}] Stack trace:\n{error.stack_trace}")
    
    def _check_error_thresholds(self):
        """Check if error rates exceed thresholds"""
        current_time = time.time()
        minute_ago = current_time - 60
        
        for severity in ErrorSeverity:
            count = len([
                e for e in self.errors
                if e.timestamp > minute_ago and e.severity == severity
            ])
            
            threshold = self.error_thresholds[severity]
            if count > threshold:
                self.logger.critical(
                    f"ERROR THRESHOLD EXCEEDED: {count} {severity.value} errors "
                    f"in last minute (threshold: {threshold})"
                )
                
                # Trigger emergency recovery if critical errors
                if severity == ErrorSeverity.CRITICAL:
                    self._emergency_recovery()
    
    def _attempt_recovery(self, error: ErrorEvent, error_id: str):
        """Attempt automatic error recovery"""
        recovery_key = f"{error.category.value}_{error.error_code}"
        
        if recovery_key in self.recovery_handlers:
            try:
                self.logger.info(f"[{error_id}] Attempting automatic recovery...")
                
                recovery_function = self.recovery_handlers[recovery_key]
                success = recovery_function(error)
                
                if success:
                    error.resolved = True
                    error.resolution_time = time.time()
                    error.recovery_actions.append(f"Auto-recovery: {recovery_key}")
                    
                    self.logger.info(f"[{error_id}] Automatic recovery successful")
                else:
                    self.logger.warning(f"[{error_id}] Automatic recovery failed")
                    
            except Exception as e:
                self.logger.error(f"[{error_id}] Recovery function failed: {e}")
    
    def _emergency_recovery(self):
        """Emergency recovery procedures for critical errors"""
        self.logger.critical("INITIATING EMERGENCY RECOVERY PROCEDURES")
        
        try:
            # Stop all gateway connections
            from connection_manager import get_connection_manager
            conn_mgr = get_connection_manager()
            conn_mgr.stop()
            
            # Clear message cache
            from message_cache import get_message_cache
            cache = get_message_cache()
            cache.clear_cache()
            
            # Wait briefly
            time.sleep(2)
            
            # Restart connection manager
            conn_mgr.start()
            
            self.logger.info("Emergency recovery completed")
            
        except Exception as e:
            self.logger.critical(f"Emergency recovery failed: {e}")
    
    def register_recovery_handler(self, category: ErrorCategory, error_code: str, 
                                handler: Callable[[ErrorEvent], bool]):
        """Register a recovery handler for specific error types"""
        recovery_key = f"{category.value}_{error_code}"
        self.recovery_handlers[recovery_key] = handler
        self.logger.info(f"Registered recovery handler for {recovery_key}")
    
    def get_error_stats(self) -> Dict:
        """Get error statistics"""
        with self.lock:
            current_time = time.time()
            hour_ago = current_time - 3600
            day_ago = current_time - 86400
            
            stats = {
                "total_errors": len(self.errors),
                "resolved_errors": len([e for e in self.errors if e.resolved]),
                "last_hour": len([e for e in self.errors if e.timestamp > hour_ago]),
                "last_24_hours": len([e for e in self.errors if e.timestamp > day_ago]),
                "by_category": {},
                "by_severity": {},
                "recent_errors": self.errors[-10:] if self.errors else []
            }
            
            # Count by category
            for category in ErrorCategory:
                stats["by_category"][category.value] = len([
                    e for e in self.errors if e.category == category
                ])
            
            # Count by severity  
            for severity in ErrorSeverity:
                stats["by_severity"][severity.value] = len([
                    e for e in self.errors if e.severity == severity
                ])
            
            return stats
    
    def resolve_error(self, error_id: str, resolution_note: str = ""):
        """Manually mark an error as resolved"""
        with self.lock:
            # Find error by ID pattern
            current_time = time.time()
            
            for error in self.errors:
                if (error_id in f"{error.category.value}_{error.error_code}_{int(error.timestamp)}" 
                    and not error.resolved):
                    error.resolved = True
                    error.resolution_time = current_time
                    error.recovery_actions.append(f"Manual: {resolution_note}")
                    
                    self.logger.info(f"Error {error_id} manually resolved: {resolution_note}")
                    return True
            
            return False
    
    def _cleanup_loop(self):
        """Background cleanup of old errors"""
        while True:
            try:
                current_time = time.time()
                week_ago = current_time - 604800  # 7 days
                
                with self.lock:
                    # Remove errors older than a week
                    original_count = len(self.errors)
                    self.errors = [e for e in self.errors if e.timestamp > week_ago]
                    removed_count = original_count - len(self.errors)
                    
                    if removed_count > 0:
                        self.logger.debug(f"Cleaned up {removed_count} old error records")
                
                # Sleep for an hour before next cleanup
                time.sleep(3600)
                
            except Exception as e:
                self.logger.error(f"Error cleanup failed: {e}")
                time.sleep(300)  # Sleep 5 minutes on error


# Specific error handlers for common scenarios
def network_error_recovery(error: ErrorEvent) -> bool:
    """Recovery handler for network errors"""
    try:
        if "connection" in error.error_code.lower():
            # Restart connection manager
            from connection_manager import get_connection_manager
            conn_mgr = get_connection_manager()
            
            # Get failed gateway from context
            gateway_ip = error.context.get("gateway_ip")
            if gateway_ip:
                conn_mgr.remove_gateway(gateway_ip)
                time.sleep(1)
                conn_mgr.add_gateway(gateway_ip)
                return True
        
        return False
        
    except Exception:
        return False


def message_error_recovery(error: ErrorEvent) -> bool:
    """Recovery handler for message errors"""
    try:
        if "ttl" in error.error_code.lower():
            # Clear message cache for TTL errors
            from message_cache import get_message_cache
            cache = get_message_cache()
            cache.clear_expired_messages()
            return True
        
        return False
        
    except Exception:
        return False


# Global error handler instance
global_error_handler = ErrorHandler()

# Register default recovery handlers
global_error_handler.register_recovery_handler(
    ErrorCategory.NETWORK, "connection_failed", network_error_recovery
)
global_error_handler.register_recovery_handler(
    ErrorCategory.MESSAGE, "ttl_expired", message_error_recovery
)


def get_error_handler() -> ErrorHandler:
    """Get the global error handler instance"""
    return global_error_handler


def handle_error(category: ErrorCategory, severity: ErrorSeverity, 
                error_code: str, message: str, exception: Optional[Exception] = None,
                context: Optional[Dict] = None, auto_recover: bool = True) -> str:
    """Convenience function for error handling"""
    return global_error_handler.handle_error(
        category, severity, error_code, message, exception, context, auto_recover
    ) 