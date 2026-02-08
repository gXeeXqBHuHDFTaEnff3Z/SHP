"""
Configuration Loader with Pydantic Schema Validation

This module implements configuration loading from YAML files with comprehensive
runtime schema validation using Pydantic. It enforces fail-fast behavior with
clear, actionable error messages.

Decision References:
    - ADR-0006: Configuration via YAML with Runtime Schema Validation
    - docs/security.md: YAML safe_load for security

Usage:
    from src.config_loader import load_config

    config = load_config("config.yaml")  # Validates and returns Config object
    print(config.model.lstm_units)  # Access with type safety

Author: GASanalysis Team
Date: 2025-10-12
Version: 1.0.0
"""

import sys
from pathlib import Path
from typing import List, Optional, Literal, Dict, Any
from pydantic import BaseModel, Field, field_validator, model_validator
import yaml


# ==============================================================================
# Custom Exceptions
# ==============================================================================

class ConfigurationError(Exception):
    """Configuration validation failed."""
    pass


class SecurityError(Exception):
    """Security constraint violated."""
    pass


# ==============================================================================
# Pydantic Configuration Models
# ==============================================================================

class ProjectConfig(BaseModel):
    """Project metadata configuration."""
    name: str = Field(..., min_length=1)
    version: str = Field(..., pattern=r"^\d+\.\d+\.\d+$")
    description: Optional[str] = None
    random_seed: int = Field(default=42, ge=0)


class PathsConfig(BaseModel):
    """File paths and data locations."""
    data_root: str = "data"
    results_root: str = "results"
    logs_root: str = "logs"
    legitimate_pcaps: str = "data/legitimate/*.pcap"
    shp_pcaps: str = "data/shp_signals/*.pcap"
    ipd_csvs_dir: str = "data"
    windows_dir: str = "data/windows"
    gas_analysis_dir: str = "results/gas_analysis"
    statistical_dir: str = "results/statistical"
    results_json: str = "results/gas_analysis/shp_arp_gaslike_results.json"
    summary_csv: str = "results/statistical/summary_table.csv"
    performance_plot: str = "results/statistical/shp_arp_detection_performance.png"
    session_manifest: str = "results/session_manifest.md"

    @field_validator('*')
    @classmethod
    def validate_no_absolute_paths(cls, v: str) -> str:
        """Prevent absolute paths (security)."""
        if v.startswith('/') or (len(v) > 1 and v[1] == ':'):  # Unix or Windows absolute
            raise SecurityError(f"Absolute paths not allowed: {v}")
        return v

    @field_validator('*')
    @classmethod
    def validate_no_path_traversal(cls, v: str) -> str:
        """Prevent path traversal attacks."""
        if '..' in v:
            raise SecurityError(f"Path traversal detected: {v}")
        return v


class ExtractionConfig(BaseModel):
    """PCAP processing and IPD extraction configuration."""
    protocol: Literal["ARP"] = "ARP"
    operation: Literal[1] = 1  # ARP request only
    ipdunit: Literal["ms"] = "ms"
    quantile_clipping: Optional[List[float]] = None
    max_pcap_size_gb: float = Field(default=5.0, gt=0, le=100)
    min_arp_requests: int = Field(default=2, ge=2)
    parallel_workers: int = Field(default=4, ge=1, le=32)

    @field_validator('quantile_clipping')
    @classmethod
    def validate_quantiles(cls, v: Optional[List[float]]) -> Optional[List[float]]:
        """Validate quantile clipping range."""
        if v is not None:
            if len(v) != 2:
                raise ValueError("quantile_clipping must be [low, high]")
            low, high = v
            if not (0 <= low < high <= 1):
                raise ValueError(f"Invalid quantiles: [{low}, {high}], must be 0 <= low < high <= 1")
        return v


class WindowingConfig(BaseModel):
    """Time series windowing configuration."""
    lengths: List[int] = Field(..., min_length=1)
    stride_factor: float = Field(default=1.0, ge=0.0, le=1.0)
    overlap: bool = False
    respect_session_boundaries: bool = True
    compression: bool = True
    dtype: Literal["float32", "float64"] = "float32"

    @field_validator('lengths')
    @classmethod
    def validate_lengths(cls, v: List[int]) -> List[int]:
        """Validate window lengths are positive and sorted."""
        if not all(length > 0 for length in v):
            raise ValueError("All window lengths must be positive")
        return sorted(v)  # Return sorted for consistency


class SessionsConfig(BaseModel):
    """Session-level train-val-test split configuration."""
    train: List[int] = Field(..., min_length=1)
    val: List[int] = Field(..., min_length=1)
    test: List[int] = Field(..., min_length=1)
    validate_no_leakage: bool = True


class DiscretizationConfig(BaseModel):
    """16-state discretization configuration."""
    num_states: int = Field(default=16, ge=2, le=256)
    method: Literal["quantile", "uniform", "variation_16"] = "quantile"
    include_derivatives: bool = True
    fit_on_train_only: bool = True


class ModelConfig(BaseModel):
    """GAS-LSTM model architecture and training configuration."""
    architecture: Literal["GAS-LSTM"] = "GAS-LSTM"
    embedding_dim: int = Field(default=100, ge=8, le=512)
    lstm_units: int = Field(default=64, ge=8, le=512)
    sequence_length: int = Field(default=8, ge=2, le=64)
    output_states: int = Field(default=16, ge=2, le=256)
    loss: str = "sparse_categorical_crossentropy"
    optimizer: str = "adam"
    learning_rate: float = Field(default=0.001, gt=0, le=1.0)
    epochs: int = Field(default=50, ge=1, le=1000)
    batch_size: int = Field(default=128, ge=1, le=10000)
    validation_split: float = Field(default=0.0, ge=0.0, le=0.5)
    early_stopping_patience: int = Field(default=5, ge=1)
    restore_best_weights: bool = True
    save_best_model: bool = True
    model_save_path: str = "results/models/gas_lstm_L{length}.h5"


class ScoringConfig(BaseModel):
    """Anomaly scoring configuration."""
    method: Literal["mean_cce_loss"] = "mean_cce_loss"
    batch_size: int = Field(default=256, ge=1)
    normalize_scores: bool = False


class MetricsConfig(BaseModel):
    """Performance metrics configuration."""
    bootstrap_resamples: int = Field(default=1000, ge=100, le=10000)
    confidence_level: float = Field(default=0.95, gt=0.0, lt=1.0)
    stratified_sampling: bool = True
    metrics: List[str] = ["auc", "tpr_at_fpr_1pct"]
    fpr_thresholds: List[float] = [0.01, 0.05, 0.10]


class LoggingConfig(BaseModel):
    """Logging configuration."""
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    format: Literal["json", "text"] = "json"
    console_enabled: bool = True
    console_colors: bool = True
    file_enabled: bool = True
    log_file: str = "logs/gas_analysis.log"
    rotation: str = "10MB"
    backup_count: int = Field(default=5, ge=1, le=100)
    include_adr_ids: bool = True
    progress_bars: bool = True


class PerformanceConfig(BaseModel):
    """Performance and resource configuration."""
    gpu_enabled: bool = True
    gpu_memory_growth: bool = True
    num_workers: int = Field(default=4, ge=1, le=128)
    inter_op_parallelism: int = Field(default=1, ge=1, le=128)
    intra_op_parallelism: int = Field(default=1, ge=1, le=128)
    cache_windows: bool = True
    batch_processing: bool = True
    pcap_parse_timeout_sec: int = Field(default=600, ge=60)
    training_timeout_sec: int = Field(default=3600, ge=60)


class ValidationConfig(BaseModel):
    """Validation and quality assurance configuration."""
    validate_pcap_integrity: bool = True
    validate_session_counts: bool = True
    min_ipd_ms: float = Field(default=0.1, gt=0)
    max_ipd_ms: float = Field(default=10000.0, gt=0)
    check_no_session_leakage: bool = True
    check_discretizer_fit: bool = True
    verify_reproducibility: bool = True
    tolerance: float = Field(default=1e-6, gt=0)


class AblationsConfig(BaseModel):
    """Ablation studies configuration."""
    enabled: bool = False
    sequence_lengths: List[int] = [4, 8, 16]
    discretization_methods: List[str] = ["quantile", "uniform"]
    quantile_ranges: List[List[float]] = [[0.4, 0.6], [0.3, 0.7]]
    include_arp_replies: bool = False


class OutputConfig(BaseModel):
    """Output and reporting configuration."""
    json_indent: int = Field(default=2, ge=0, le=8)
    csv_sep: str = ","
    figure_dpi: int = Field(default=300, ge=72, le=600)
    figure_format: Literal["png", "pdf", "svg"] = "png"
    plot_style: str = "seaborn-v0_8-darkgrid"
    include_metadata: bool = True
    include_config_snapshot: bool = True


class ExperimentConfig(BaseModel):
    """Experimental configuration."""
    name: str = "SHP_ARP_Detectability_GAS"
    date: str
    platform: Literal["linux", "windows", "darwin"] = "linux"
    python_version: str = "3.10"
    shp_distances: List[int] = [50, 100, 200, 500, 1000]
    sessions_per_distance: int = Field(default=15, ge=1)
    capture_duration_min: int = Field(default=20, ge=1)
    notes: Optional[str] = None


class SecurityConfig(BaseModel):
    """Safety and security configuration."""
    allow_absolute_paths: bool = False
    max_path_length: int = Field(default=256, ge=32, le=4096)
    restrict_to_project_dir: bool = True
    disable_eval: bool = True
    disable_shell_commands: bool = True


class DebugConfig(BaseModel):
    """Developer and debug configuration."""
    enabled: bool = False
    tf_log_device_placement: bool = False
    tf_enable_eager_execution: bool = False
    profile_stages: bool = False
    memory_profiling: bool = False
    dry_run: bool = False
    use_small_dataset: bool = False
    skip_gpu: bool = False


# ==============================================================================
# Main Configuration Model
# ==============================================================================

class Config(BaseModel):
    """
    Root configuration model.

    Decision: ADR-0006 (Configuration via YAML with Runtime Schema Validation)
    """
    project: ProjectConfig
    paths: PathsConfig
    extraction: ExtractionConfig
    windowing: WindowingConfig
    sessions: SessionsConfig
    discretization: DiscretizationConfig
    model: ModelConfig
    scoring: ScoringConfig
    metrics: MetricsConfig
    logging: LoggingConfig
    performance: PerformanceConfig
    validation: ValidationConfig
    ablations: AblationsConfig
    output: OutputConfig
    experiment: ExperimentConfig
    security: SecurityConfig
    debug: DebugConfig

    @model_validator(mode='after')
    def validate_cross_field_constraints(self) -> 'Config':
        """
        Validate constraints across multiple fields.

        Decision: ADR-0006 (Fail-fast validation)
        """
        errors = []

        # Validate sequence_length < min(window_lengths)
        min_window = min(self.windowing.lengths)
        if self.model.sequence_length >= min_window:
            errors.append(
                f"model.sequence_length ({self.model.sequence_length}) must be < "
                f"min(windowing.lengths) ({min_window})"
            )

        # Validate output_states == discretization.num_states
        if self.model.output_states != self.discretization.num_states:
            errors.append(
                f"model.output_states ({self.model.output_states}) must equal "
                f"discretization.num_states ({self.discretization.num_states})"
            )

        # Validate no session overlap
        if self.sessions.validate_no_leakage:
            train_set = set(self.sessions.train)
            val_set = set(self.sessions.val)
            test_set = set(self.sessions.test)

            if train_set & val_set:
                errors.append(f"Train/val session overlap: {train_set & val_set}")
            if train_set & test_set:
                errors.append(f"Train/test session overlap: {train_set & test_set}")
            if val_set & test_set:
                errors.append(f"Val/test session overlap: {val_set & test_set}")

        if errors:
            error_msg = "Configuration validation failed:\n" + "\n".join(
                f"  - {err}" for err in errors
            )
            raise ConfigurationError(error_msg)

        return self


# ==============================================================================
# Configuration Loading
# ==============================================================================

def load_config(config_path: str = "config.yaml") -> Config:
    """
    Load and validate configuration from YAML file.

    This function uses yaml.safe_load() to prevent code execution attacks,
    then validates the configuration against Pydantic schemas with fail-fast
    error reporting.

    Args:
        config_path: Path to YAML configuration file (default: "config.yaml")

    Returns:
        Validated Config object

    Raises:
        FileNotFoundError: If configuration file not found
        yaml.YAMLError: If YAML syntax is invalid
        ConfigurationError: If validation fails

    Decision References:
        - ADR-0006: YAML Configuration with Schema Validation
        - docs/security.md: yaml.safe_load() prevents code execution

    Example:
        >>> config = load_config("config.yaml")
        >>> print(config.model.lstm_units)
        64
    """
    # Check file exists
    config_file = Path(config_path)
    if not config_file.exists():
        raise FileNotFoundError(
            f"Configuration file not found: {config_path}\n"
            f"Expected location: {config_file.absolute()}\n"
            f"Decision: ADR-0006 (Configuration Validation)"
        )

    # Load YAML safely (no code execution)
    try:
        with open(config_file, 'r') as f:
            raw_config = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ConfigurationError(
            f"Invalid YAML syntax in {config_path}:\n{e}\n"
            f"Decision: ADR-0006 (Configuration Validation)"
        )

    # Validate with Pydantic
    try:
        config = Config(**raw_config)
    except Exception as e:
        raise ConfigurationError(
            f"Configuration validation failed:\n{e}\n\n"
            f"Fix the errors in {config_path} and try again.\n"
            f"Decision: ADR-0006 (Fail-Fast Configuration Validation)"
        )

    return config


def validate_config_file(config_path: str = "config.yaml") -> bool:
    """
    Validate configuration file without loading.

    Useful for CI/CD pipelines to check configuration validity.

    Args:
        config_path: Path to YAML configuration file

    Returns:
        True if valid, False otherwise (prints errors)

    Example:
        >>> if validate_config_file("config.yaml"):
        ...     print("Configuration is valid")
    """
    try:
        config = load_config(config_path)
        print(f"✓ Configuration valid: {config.project.name} v{config.project.version}")
        return True
    except Exception as e:
        print(f"✗ Configuration validation failed:\n{e}")
        return False


# ==============================================================================
# CLI Entry Point (for validation)
# ==============================================================================

if __name__ == "__main__":
    """
    Standalone validation mode.

    Usage:
        python src/config_loader.py                # Validate default config.yaml
        python src/config_loader.py custom.yaml    # Validate custom file
    """
    import sys

    config_file = sys.argv[1] if len(sys.argv) > 1 else "config.yaml"

    print(f"Validating configuration: {config_file}")
    print("=" * 70)

    if validate_config_file(config_file):
        print("=" * 70)
        print("Configuration validation: PASSED ✓")
        sys.exit(0)
    else:
        print("=" * 70)
        print("Configuration validation: FAILED ✗")
        sys.exit(1)
