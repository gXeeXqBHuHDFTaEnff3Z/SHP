"""
JSON-Structured Logger with ADR Traceability

This module implements comprehensive logging with JSON structuring for machine
readability, colored console output for human readability, and ADR ID traceability
for architectural decision tracking.

Decision References:
    - ADR-0009: JSON-Structured Logging with ADR Traceability
    - docs/conventions.md: Logging Standards
    - docs/ops.md: Observability and Monitoring

Features:
    - JSON-structured file logging (10MB rotation, 5 backups)
    - Colored console output (yellow warnings, red errors)
    - ADR ID injection for traceability
    - Configurable log levels (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    - Progress bar support (toggled via config)
    - Context managers for stage logging

Usage:
    from src.config_loader import load_config
    from src.logger import setup_logger

    config = load_config("config.yaml")
    logger = setup_logger(config)

    logger.info("Starting extraction", extra={"adr_id": "ADR-0001"})
    logger.warning("High memory usage detected", extra={"memory_gb": 4.5})
    logger.error("Model training failed", extra={"adr_id": "ADR-0002", "epoch": 15})

Author: GASanalysis Team
Date: 2025-10-12
Version: 1.0.0
"""

import sys
import logging
import json
from pathlib import Path
from typing import Optional, Dict, Any
from logging.handlers import RotatingFileHandler
from pythonjsonlogger import jsonlogger
from colorama import Fore, Style, init as colorama_init


# ==============================================================================
# Custom Exceptions
# ==============================================================================

class LoggerError(Exception):
    """Logger configuration or operation failed."""
    pass


# ==============================================================================
# Colored Console Formatter
# ==============================================================================

class ColoredConsoleFormatter(logging.Formatter):
    """
    Console formatter with colored output by log level.

    Decision: ADR-0009 (Human-readable console logs with color coding)
    """

    # Color mapping for log levels
    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Style.BRIGHT,
    }

    def __init__(self, fmt: Optional[str] = None, datefmt: Optional[str] = None):
        """
        Initialize colored formatter.

        Args:
            fmt: Log message format string
            datefmt: Date format string
        """
        super().__init__(fmt, datefmt)
        colorama_init(autoreset=True)  # Initialize colorama for cross-platform support

    def format(self, record: logging.LogRecord) -> str:
        """
        Format log record with color coding.

        Args:
            record: Log record to format

        Returns:
            Colored formatted log string
        """
        # Add color to levelname
        levelname = record.levelname
        if levelname in self.COLORS:
            record.levelname = f"{self.COLORS[levelname]}{levelname}{Style.RESET_ALL}"

        # Format the record
        formatted = super().format(record)

        # Reset levelname (in case record is reused)
        record.levelname = levelname

        return formatted


# ==============================================================================
# JSON File Formatter with ADR Traceability
# ==============================================================================

class ADRJSONFormatter(jsonlogger.JsonFormatter):
    """
    JSON formatter that includes ADR IDs and custom fields.

    Decision: ADR-0009 (JSON-structured logging with ADR traceability)
    """

    def add_fields(self, log_record: Dict[str, Any], record: logging.LogRecord, message_dict: Dict[str, Any]):
        """
        Add custom fields to JSON log record.

        Args:
            log_record: Dictionary being built for JSON output
            record: Python logging record
            message_dict: Additional fields from extra parameter
        """
        super().add_fields(log_record, record, message_dict)

        # Add standard fields
        log_record['timestamp'] = self.formatTime(record, self.datefmt)
        log_record['level'] = record.levelname
        log_record['logger'] = record.name
        log_record['module'] = record.module
        log_record['function'] = record.funcName
        log_record['line'] = record.lineno

        # Add ADR ID if provided
        if hasattr(record, 'adr_id'):
            log_record['adr_id'] = record.adr_id

        # Add any custom fields from extra parameter
        for key, value in message_dict.items():
            if key not in log_record:
                log_record[key] = value


# ==============================================================================
# ADR-Aware Logger Adapter
# ==============================================================================

class ADRLoggerAdapter(logging.LoggerAdapter):
    """
    Logger adapter that simplifies ADR ID injection.

    Decision: ADR-0009 (ADR traceability in logs)

    Usage:
        logger.info("Message", extra={"adr_id": "ADR-0001"})
        # or use convenience method
        logger.log_with_adr("INFO", "Message", "ADR-0001")
    """

    def __init__(self, logger: logging.Logger, extra: Optional[Dict[str, Any]] = None):
        """
        Initialize ADR logger adapter.

        Args:
            logger: Base logger instance
            extra: Additional context to include in all logs
        """
        super().__init__(logger, extra or {})

    def process(self, msg: str, kwargs: Dict[str, Any]) -> tuple:
        """
        Process log message to inject ADR context.

        Args:
            msg: Log message
            kwargs: Logging keyword arguments

        Returns:
            Tuple of (message, kwargs) with ADR context added
        """
        # Merge adapter's extra with call-specific extra
        extra = kwargs.get('extra', {})
        extra.update(self.extra)
        kwargs['extra'] = extra

        return msg, kwargs

    def log_with_adr(self, level: str, msg: str, adr_id: str, **kwargs):
        """
        Convenience method to log with ADR ID.

        Args:
            level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            msg: Log message
            adr_id: ADR identifier (e.g., "ADR-0001")
            **kwargs: Additional fields to include
        """
        extra = kwargs.pop('extra', {})
        extra['adr_id'] = adr_id
        extra.update(kwargs)

        log_method = getattr(self.logger, level.lower())
        log_method(msg, extra=extra)


# ==============================================================================
# Logger Setup
# ==============================================================================

def setup_logger(config: Any, name: str = "GASanalysis") -> ADRLoggerAdapter:
    """
    Setup comprehensive logging system from configuration.

    This function creates a logger with:
    - JSON-structured file logging with rotation
    - Colored console logging for human readability
    - ADR ID traceability support
    - Configurable log levels and formats

    Args:
        config: Configuration object from config_loader.load_config()
        name: Logger name (default: "GASanalysis")

    Returns:
        ADRLoggerAdapter instance with file and console handlers

    Raises:
        LoggerError: If logger setup fails

    Decision References:
        - ADR-0009: JSON-Structured Logging with ADR Traceability
        - docs/ops.md: Logging for observability

    Example:
        >>> from src.config_loader import load_config
        >>> from src.logger import setup_logger
        >>>
        >>> config = load_config("config.yaml")
        >>> logger = setup_logger(config)
        >>>
        >>> logger.info("Pipeline started", extra={"adr_id": "ADR-0007"})
        >>> logger.warning("High memory usage", extra={"memory_gb": 4.5})
        >>> logger.error("Training failed", extra={"adr_id": "ADR-0002", "epoch": 15})
    """
    # Get logging configuration
    log_config = config.logging

    # Create base logger
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, log_config.level))

    # Clear any existing handlers (prevent duplicates)
    logger.handlers.clear()

    # ====================
    # File Handler (JSON)
    # ====================

    if log_config.file_enabled:
        try:
            # Ensure log directory exists
            log_file = Path(log_config.log_file)
            log_file.parent.mkdir(parents=True, exist_ok=True)

            # Parse rotation size (e.g., "10MB" -> 10 * 1024 * 1024)
            rotation_size = _parse_size(log_config.rotation)

            # Create rotating file handler
            file_handler = RotatingFileHandler(
                filename=log_file,
                maxBytes=rotation_size,
                backupCount=log_config.backup_count,
                encoding='utf-8'
            )
            file_handler.setLevel(getattr(logging, log_config.level))

            # Set JSON formatter
            json_formatter = ADRJSONFormatter(
                fmt='%(timestamp)s %(level)s %(name)s %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            file_handler.setFormatter(json_formatter)

            # Add handler to logger
            logger.addHandler(file_handler)

        except Exception as e:
            raise LoggerError(f"Failed to setup file logging: {e}")

    # ====================
    # Console Handler (Colored Text)
    # ====================

    if log_config.console_enabled:
        try:
            # Create console handler
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(getattr(logging, log_config.level))

            # Set formatter (colored or plain)
            if log_config.console_colors:
                console_format = '%(asctime)s | %(levelname)s | %(name)s | %(message)s'
                console_formatter = ColoredConsoleFormatter(
                    fmt=console_format,
                    datefmt='%H:%M:%S'
                )
            else:
                console_format = '%(asctime)s | %(levelname)s | %(name)s | %(message)s'
                console_formatter = logging.Formatter(
                    fmt=console_format,
                    datefmt='%H:%M:%S'
                )

            console_handler.setFormatter(console_formatter)

            # Add handler to logger
            logger.addHandler(console_handler)

        except Exception as e:
            raise LoggerError(f"Failed to setup console logging: {e}")

    # Wrap in ADR-aware adapter
    adapter = ADRLoggerAdapter(logger, extra={'project': config.project.name})

    # Log initialization success
    adapter.info(
        f"Logger initialized: {name}",
        extra={
            'adr_id': 'ADR-0009',
            'log_level': log_config.level,
            'file_logging': log_config.file_enabled,
            'console_logging': log_config.console_enabled
        }
    )

    return adapter


def _parse_size(size_str: str) -> int:
    """
    Parse size string to bytes.

    Args:
        size_str: Size string (e.g., "10MB", "1GB", "512KB")

    Returns:
        Size in bytes

    Raises:
        ValueError: If size string is invalid

    Example:
        >>> _parse_size("10MB")
        10485760
        >>> _parse_size("1GB")
        1073741824
    """
    size_str = size_str.upper().strip()

    # Extract number and unit
    import re
    match = re.match(r'(\d+(?:\.\d+)?)\s*([KMGT]?B)', size_str)

    if not match:
        raise ValueError(f"Invalid size format: {size_str} (expected format: '10MB', '1GB', etc.)")

    number = float(match.group(1))
    unit = match.group(2)

    # Convert to bytes
    multipliers = {
        'B': 1,
        'KB': 1024,
        'MB': 1024 ** 2,
        'GB': 1024 ** 3,
        'TB': 1024 ** 4
    }

    if unit not in multipliers:
        raise ValueError(f"Unknown size unit: {unit}")

    return int(number * multipliers[unit])


# ==============================================================================
# Context Managers for Stage Logging
# ==============================================================================

class LogStage:
    """
    Context manager for logging pipeline stages.

    Decision: ADR-0007 (Modular pipeline with stage tracking)

    Usage:
        with LogStage(logger, "Extraction", "ADR-0001"):
            # Extraction code here
            pass
        # Logs "Stage started" and "Stage completed" with timing
    """

    def __init__(self, logger: ADRLoggerAdapter, stage_name: str, adr_id: str):
        """
        Initialize stage logger.

        Args:
            logger: ADR-aware logger adapter
            stage_name: Name of the stage (e.g., "Extraction", "Training")
            adr_id: Relevant ADR ID for this stage
        """
        self.logger = logger
        self.stage_name = stage_name
        self.adr_id = adr_id
        self.start_time = None

    def __enter__(self):
        """Log stage start."""
        import time
        self.start_time = time.time()
        self.logger.info(
            f"Stage started: {self.stage_name}",
            extra={'adr_id': self.adr_id, 'stage': self.stage_name, 'event': 'stage_start'}
        )
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Log stage completion or failure."""
        import time
        duration = time.time() - self.start_time

        if exc_type is None:
            # Success
            self.logger.info(
                f"Stage completed: {self.stage_name}",
                extra={
                    'adr_id': self.adr_id,
                    'stage': self.stage_name,
                    'event': 'stage_complete',
                    'duration_sec': round(duration, 2)
                }
            )
        else:
            # Failure
            self.logger.error(
                f"Stage failed: {self.stage_name}",
                extra={
                    'adr_id': self.adr_id,
                    'stage': self.stage_name,
                    'event': 'stage_failed',
                    'duration_sec': round(duration, 2),
                    'error': str(exc_val)
                }
            )

        # Don't suppress exceptions
        return False


# ==============================================================================
# Convenience Functions
# ==============================================================================

def get_logger(name: str = "GASanalysis") -> logging.Logger:
    """
    Get existing logger by name.

    Args:
        name: Logger name (default: "GASanalysis")

    Returns:
        Logger instance

    Note:
        This retrieves an existing logger. Use setup_logger() for initial setup.
    """
    return logging.getLogger(name)


def set_log_level(logger: logging.Logger, level: str):
    """
    Change log level at runtime.

    Args:
        logger: Logger instance
        level: New log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)

    Example:
        >>> logger = get_logger()
        >>> set_log_level(logger, "DEBUG")
    """
    logger.setLevel(getattr(logging, level.upper()))

    # Also update handlers
    for handler in logger.handlers:
        handler.setLevel(getattr(logging, level.upper()))


def log_config_snapshot(logger: ADRLoggerAdapter, config: Any):
    """
    Log configuration snapshot for reproducibility.

    Args:
        logger: Logger instance
        config: Configuration object from config_loader

    Decision: ADR-0010 (Reproducibility tracking)
    """
    logger.info(
        "Configuration snapshot",
        extra={
            'adr_id': 'ADR-0010',
            'event': 'config_snapshot',
            'project_name': config.project.name,
            'project_version': config.project.version,
            'random_seed': config.project.random_seed,
            'window_lengths': config.windowing.lengths,
            'sequence_length': config.model.sequence_length,
            'lstm_units': config.model.lstm_units
        }
    )


# ==============================================================================
# CLI Entry Point (for testing)
# ==============================================================================

if __name__ == "__main__":
    """
    Standalone testing mode.

    Usage:
        python src/logger.py
    """
    from pathlib import Path
    import sys

    # Add parent directory to path
    sys.path.insert(0, str(Path(__file__).parent.parent))

    from src.config_loader import load_config

    print("Testing logger module...\n")
    print("=" * 70)

    # Load configuration
    try:
        config = load_config("config.yaml")
    except Exception as e:
        print(f"Error loading config: {e}")
        sys.exit(1)

    # Setup logger
    try:
        logger = setup_logger(config, name="TestLogger")
    except Exception as e:
        print(f"Error setting up logger: {e}")
        sys.exit(1)

    print("\nTesting log levels:\n")

    # Test different log levels
    logger.debug("This is a DEBUG message", extra={'test': 'debug'})
    logger.info("This is an INFO message", extra={'test': 'info'})
    logger.warning("This is a WARNING message", extra={'test': 'warning'})
    logger.error("This is an ERROR message", extra={'test': 'error'})

    # Test ADR traceability
    print("\nTesting ADR traceability:\n")
    logger.info("Testing ADR-0001", extra={'adr_id': 'ADR-0001', 'component': 'extractor'})
    logger.info("Testing ADR-0002", extra={'adr_id': 'ADR-0002', 'component': 'gas_model'})

    # Test convenience method
    print("\nTesting convenience method:\n")
    logger.log_with_adr("INFO", "Using convenience method", "ADR-0009", custom_field="custom_value")

    # Test stage logging
    print("\nTesting stage logging:\n")
    try:
        with LogStage(logger, "TestStage", "ADR-0007"):
            import time
            time.sleep(0.5)  # Simulate work
    except Exception as e:
        print(f"Stage logging test failed: {e}")

    # Test configuration snapshot
    print("\nTesting configuration snapshot:\n")
    log_config_snapshot(logger, config)

    print("\n" + "=" * 70)
    print("Logger testing complete! Check logs/gas_analysis.log for JSON output.")
    print("=" * 70)
