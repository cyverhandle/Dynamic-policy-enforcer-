"""
Logging Configuration for Threat Intelligence Platform
Provides structured logging with rotation and severity levels
"""

import logging
import logging.handlers
import sys
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

# Global logger instances
_loggers = {}
_log_format = None
_log_handlers = []


class JSONFormatter(logging.Formatter):
    """
    JSON formatter for structured logging
    Useful for SIEM integration
    """
    
    def format(self, record):
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }
        
        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        
        # Add extra fields
        if hasattr(record, 'extra_data'):
            log_entry["extra"] = record.extra_data
        
        return json.dumps(log_entry)


class ColoredFormatter(logging.Formatter):
    """
    Colored formatter for console output
    """
    
    # ANSI color codes
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
        'RESET': '\033[0m'
    }
    
    def format(self, record):
        # Add color to level name
        levelname = record.levelname
        if levelname in self.COLORS:
            record.levelname = f"{self.COLORS[levelname]}{levelname}{self.COLORS['RESET']}"
        
        return super().format(record)


def setup_logging(log_level: str = "INFO",
                  log_file: str = "logs/threat_intel.log",
                  max_bytes: int = 10485760,  # 10MB
                  backup_count: int = 5,
                  json_format: bool = False,
                  console_output: bool = True):
    """
    Setup logging configuration for the application
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path to log file
        max_bytes: Maximum size of log file before rotation
        backup_count: Number of backup files to keep
        json_format: Use JSON format for logs (for SIEM)
        console_output: Output logs to console
    """
    global _log_handlers
    
    # Create log directory if it doesn't exist
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Set log level
    level = getattr(logging, log_level.upper(), logging.INFO)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
        if handler in _log_handlers:
            _log_handlers.remove(handler)
    
    # File handler with rotation
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=max_bytes,
        backupCount=backup_count
    )
    
    if json_format:
        file_formatter = JSONFormatter()
    else:
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    file_handler.setFormatter(file_formatter)
    root_logger.addHandler(file_handler)
    _log_handlers.append(file_handler)
    
    # Console handler
    if console_output:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        
        if sys.stdout.isatty():  # Use colored output for terminal
            console_formatter = ColoredFormatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
        else:
            console_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
        
        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)
        _log_handlers.append(console_handler)
    
    # Suppress noisy loggers
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("pymongo").setLevel(logging.WARNING)
    
    # Log startup message
    root_logger.info(f"Logging initialized - Level: {log_level}, File: {log_file}")
    
    return root_logger


def get_logger(name: str, extra_fields: Optional[Dict[str, Any]] = None) -> logging.Logger:
    """
    Get a logger instance with optional extra fields
    
    Args:
        name: Logger name (typically __name__)
        extra_fields: Dictionary of extra fields to include in log entries
    
    Returns:
        Logger instance
    """
    if name in _loggers:
        return _loggers[name]
    
    logger = logging.getLogger(name)
    
    # Create adapter for extra fields
    if extra_fields:
        logger = logging.LoggerAdapter(logger, extra_fields)
    
    _loggers[name] = logger
    return logger


class AuditLogger:
    """
    Specialized logger for security audit events
    Complies with PCI-DSS requirements
    """
    
    def __init__(self, db_client=None):
        self.db_client = db_client
        self.logger = get_logger("audit")
    
    def log_security_event(self, event_type: str, user: str, 
                          resource: str, action: str, 
                          status: str, details: Dict[str, Any]):
        """
        Log a security event for compliance
        
        Args:
            event_type: Type of event (auth, access, modify, etc.)
            user: User who performed the action
            resource: Resource affected
            action: Action performed
            status: Success or failure
            details: Additional event details
        """
        log_data = {
            "event_type": event_type,
            "user": user,
            "resource": resource,
            "action": action,
            "status": status,
            "timestamp": datetime.utcnow().isoformat(),
            "details": details
        }
        
        # Log to file
        self.logger.info(f"SECURITY_EVENT: {json.dumps(log_data)}")
        
        # Store in database if available
        if self.db_client:
            try:
                self.db_client.db.security_events.insert_one(log_data)
            except Exception as e:
                self.logger.error(f"Failed to log security event to DB: {e}")
    
    def log_access(self, user: str, resource: str, action: str, success: bool):
        """Log access to system resources"""
        self.log_security_event(
            event_type="access",
            user=user,
            resource=resource,
            action=action,
            status="success" if success else "failure",
            details={"ip": "unknown"}  # Could be enhanced with request IP
        )
    
    def log_config_change(self, user: str, config_section: str, 
                         old_value: Any, new_value: Any):
        """Log configuration changes"""
        self.log_security_event(
            event_type="config_change",
            user=user,
            resource=config_section,
            action="modify",
            status="success",
            details={"old": str(old_value), "new": str(new_value)}
        )


class MetricsLogger:
    """
    Logger for performance metrics and operational data
    """
    
    def __init__(self):
        self.logger = get_logger("metrics")
    
    def log_threat_processing(self, feed_name: str, indicators_count: int, 
                             processing_time_ms: float, success: bool):
        """Log threat feed processing metrics"""
        self.logger.info(json.dumps({
            "type": "threat_processing",
            "feed": feed_name,
            "indicators": indicators_count,
            "processing_time_ms": processing_time_ms,
            "success": success,
            "timestamp": datetime.utcnow().isoformat()
        }))
    
    def log_block_operation(self, indicator: str, operation: str, success: bool):
        """Log firewall block operations"""
        self.logger.info(json.dumps({
            "type": "block_operation",
            "indicator": indicator,
            "operation": operation,
            "success": success,
            "timestamp": datetime.utcnow().isoformat()
        }))
    
    def log_system_health(self, component: str, status: str, details: Dict[str, Any]):
        """Log system health metrics"""
        self.logger.info(json.dumps({
            "type": "system_health",
            "component": component,
            "status": status,
            "details": details,
            "timestamp": datetime.utcnow().isoformat()
        }))


# Initialize default logging on module import
setup_logging()

# Export main classes
__all__ = [
    "setup_logging",
    "get_logger",
    "AuditLogger",
    "MetricsLogger",
    "JSONFormatter",
    "ColoredFormatter"
                    ]
