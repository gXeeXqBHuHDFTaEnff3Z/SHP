"""
GASanalysis Source Package

This package contains all core modules for the GAS-style detectability analysis
of SHP ARP signaling.

Modules:
    - config_loader: Configuration loading and validation (ADR-0006)
    - logger: JSON-structured logging with ADR traceability (ADR-0009)
    - extractor: ARP IPD extraction from PCAP files (ADR-0001)
    - windowing: Time series windowing (ADR-0003)
    - discretizer: 16-state discretization (ADR-0005)
    - gas_model: GAS-LSTM model architecture (ADR-0002)
    - trainer: Model training logic (ADR-0002)
    - scorer: Anomaly scoring (ADR-0002)
    - metrics: Bootstrap confidence intervals (ADR-0008)
    - visualization: Results plotting

Decision References:
    - ADR-0007: Modular Pipeline Architecture
    - docs/technical_design.md: Component specifications

Author: GASanalysis Team
Date: 2025-10-12
Version: 1.0.0
"""

__version__ = "1.0.0"
__author__ = "GASanalysis Team"

# Package-level imports for convenience
# (Uncomment as modules are implemented)

# from .config_loader import load_config, Config
# from .logger import setup_logger
# from .extractor import extract_arp_ipds
# from .windowing import create_windows
# from .discretizer import IPDDiscretizer
# from .gas_model import build_gas_lstm_model
# from .trainer import train_gas_model
# from .scorer import score_windows
# from .metrics import bootstrap_metrics
# from .visualization import plot_detection_performance

__all__ = [
    "load_config",
    "Config",
    "setup_logger",
    "extract_arp_ipds",
    "create_windows",
    "IPDDiscretizer",
    "build_gas_lstm_model",
    "train_gas_model",
    "score_windows",
    "bootstrap_metrics",
    "plot_detection_performance",
]
