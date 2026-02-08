"""
Configuration Validator Module

Validates config.yaml schema and values (ADR-0006).
Implements fail-fast validation with clear error messages.
"""

import yaml
import logging
from pathlib import Path
from typing import Dict, Any


class ConfigurationError(Exception):
    """Raised when configuration validation fails."""
    pass


class ConfigValidator:
    """
    Validates configuration file schema and values.

    Implements ADR-0006: Configuration Validation Strategy
    """

    def __init__(self, config_path: str):
        """
        Initialize validator.

        Args:
            config_path: Path to config.yaml file

        Raises:
            ConfigurationError: If config file doesn't exist
        """
        self.config_path = Path(config_path)
        self.config = None
        self.logger = logging.getLogger(__name__)

        if not self.config_path.exists():
            raise ConfigurationError(f"Configuration file not found: {config_path}")

    def validate(self) -> Dict[str, Any]:
        """
        Validate configuration schema and values.

        Returns:
            Validated configuration dictionary

        Raises:
            ConfigurationError: If validation fails
        """
        self.logger.info(f"Validating configuration: {self.config_path}")

        # Load YAML
        try:
            with open(self.config_path, 'r') as f:
                self.config = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise ConfigurationError(f"Invalid YAML syntax: {e}")

        if self.config is None:
            raise ConfigurationError("Configuration file is empty")

        # Validate sections
        self._validate_detection_params()
        self._validate_preprocessing_params()
        self._validate_isolation_forest_params()
        self._validate_thresholds()
        self._validate_input_output()
        self._validate_logging()

        self.logger.info("✓ Configuration validation passed")
        return self.config

    def _validate_detection_params(self):
        """Validate detection parameters (ADR-0002, ADR-0004)."""
        if 'detection' not in self.config:
            raise ConfigurationError("Missing required section: 'detection'")

        detection = self.config['detection']

        # window_size
        if 'window_size' not in detection:
            raise ConfigurationError("Missing required field: detection.window_size")

        window_size = detection['window_size']
        if not isinstance(window_size, int) or window_size <= 0:
            raise ConfigurationError(
                f"detection.window_size must be int > 0, got {window_size}"
            )

        if window_size < 100:
            self.logger.warning(
                f"detection.window_size={window_size} is very small. "
                "Paper recommends 200-500 for good accuracy."
            )

        # max_tree_depth
        if 'max_tree_depth' not in detection:
            raise ConfigurationError("Missing required field: detection.max_tree_depth")

        max_depth = detection['max_tree_depth']
        if not isinstance(max_depth, int) or max_depth <= 0:
            raise ConfigurationError(
                f"detection.max_tree_depth must be int > 0, got {max_depth}"
            )

        # n_trees (ensemble)
        if 'n_trees' not in detection:
            raise ConfigurationError("Missing required field: detection.n_trees")

        n_trees = detection['n_trees']
        if not isinstance(n_trees, int) or n_trees <= 0:
            raise ConfigurationError(
                f"detection.n_trees must be int > 0, got {n_trees}"
            )

        if n_trees < 10:
            self.logger.warning(
                f"detection.n_trees={n_trees} is very small. "
                "Recommended: 100 for stable results (ADR-0002)."
            )

        # aggregation_method
        valid_methods = ['mean', 'median', 'mode']
        aggregation = detection.get('aggregation_method', 'median')
        if aggregation not in valid_methods:
            raise ConfigurationError(
                f"detection.aggregation_method must be one of {valid_methods}, "
                f"got '{aggregation}'"
            )

        # random_seed
        if 'random_seed' not in detection:
            raise ConfigurationError("Missing required field: detection.random_seed")

        seed = detection['random_seed']
        if not isinstance(seed, int):
            raise ConfigurationError(
                f"detection.random_seed must be int, got {type(seed).__name__}"
            )

    def _validate_preprocessing_params(self):
        """Validate IAT preprocessing parameters (ADR-0005)."""
        if 'preprocessing' not in self.config:
            raise ConfigurationError("Missing required section: 'preprocessing'")

        preprocessing = self.config['preprocessing']

        # min_iat_sec
        if 'min_iat_sec' not in preprocessing:
            raise ConfigurationError("Missing required field: preprocessing.min_iat_sec")

        min_iat = preprocessing['min_iat_sec']
        if not isinstance(min_iat, (int, float)) or min_iat <= 0:
            raise ConfigurationError(
                f"preprocessing.min_iat_sec must be number > 0, got {min_iat}"
            )

        # Sanity check: warn if too small (ADR-0005)
        if min_iat < 1e-6:  # < 1 microsecond
            self.logger.warning(
                f"preprocessing.min_iat_sec={min_iat} is unusually small (<1 µs). "
                "Did you mean seconds, not milliseconds? (ADR-0005)"
            )

        # max_iat_sec
        if 'max_iat_sec' not in preprocessing:
            raise ConfigurationError("Missing required field: preprocessing.max_iat_sec")

        max_iat = preprocessing['max_iat_sec']
        if not isinstance(max_iat, (int, float)) or max_iat <= 0:
            raise ConfigurationError(
                f"preprocessing.max_iat_sec must be number > 0, got {max_iat}"
            )

        # min < max
        if min_iat >= max_iat:
            raise ConfigurationError(
                f"preprocessing.max_iat_sec ({max_iat}) must be > "
                f"min_iat_sec ({min_iat})"
            )

        # Sanity check: warn if too large
        if max_iat > 10:  # > 10 seconds
            self.logger.warning(
                f"preprocessing.max_iat_sec={max_iat} is unusually large (>10 s). "
                "This may include idle/timeout periods."
            )

    def _validate_isolation_forest_params(self):
        """Validate Isolation Forest parameters (ADR-0001)."""
        if 'isolation_forest' not in self.config:
            raise ConfigurationError("Missing required section: 'isolation_forest'")

        iforest = self.config['isolation_forest']

        # n_estimators
        if 'n_estimators' not in iforest:
            raise ConfigurationError("Missing required field: isolation_forest.n_estimators")

        n_est = iforest['n_estimators']
        if not isinstance(n_est, int) or n_est <= 0:
            raise ConfigurationError(
                f"isolation_forest.n_estimators must be int > 0, got {n_est}"
            )

        # contamination
        if 'contamination' not in iforest:
            raise ConfigurationError("Missing required field: isolation_forest.contamination")

        contamination = iforest['contamination']
        if not isinstance(contamination, (int, float)) or not (0 < contamination < 0.5):
            raise ConfigurationError(
                f"isolation_forest.contamination must be in (0, 0.5), got {contamination}"
            )

        # random_state
        if 'random_state' not in iforest:
            raise ConfigurationError("Missing required field: isolation_forest.random_state")

        # max_samples
        if 'max_samples' not in iforest:
            raise ConfigurationError("Missing required field: isolation_forest.max_samples")

        max_samples = iforest['max_samples']
        if not isinstance(max_samples, int) or max_samples <= 0:
            raise ConfigurationError(
                f"isolation_forest.max_samples must be int > 0, got {max_samples}"
            )

    def _validate_thresholds(self):
        """Validate detection thresholds (ADR-0003)."""
        if 'thresholds' not in self.config:
            raise ConfigurationError("Missing required section: 'thresholds'")

        thresholds = self.config['thresholds']

        required_thresholds = [
            'ipctc_lnctc_max',
            'jitterbug_eklibur_max',
            'trctc_max',
            'legitimate_min',
            'legitimate_max',
            'overlap_zone_min',
            'overlap_zone_max'
        ]

        for field in required_thresholds:
            if field not in thresholds:
                raise ConfigurationError(f"Missing required field: thresholds.{field}")

            value = thresholds[field]
            if not isinstance(value, int) or value < 0:
                raise ConfigurationError(
                    f"thresholds.{field} must be int >= 0, got {value}"
                )

        # Validate threshold ordering
        if thresholds['legitimate_min'] > thresholds['legitimate_max']:
            raise ConfigurationError(
                "thresholds.legitimate_max must be >= legitimate_min"
            )

        if thresholds['overlap_zone_min'] > thresholds['overlap_zone_max']:
            raise ConfigurationError(
                "thresholds.overlap_zone_max must be >= overlap_zone_min"
            )

        # Verify overlap zone is within legitimate/TRCTC ranges (ADR-0003)
        if not (thresholds['legitimate_min'] <= thresholds['overlap_zone_min'] <= thresholds['legitimate_max']):
            self.logger.warning(
                "thresholds.overlap_zone_min should be within legitimate range (ADR-0003)"
            )

    def _validate_input_output(self):
        """Validate input/output paths."""
        if 'input' not in self.config:
            raise ConfigurationError("Missing required section: 'input'")

        if 'output' not in self.config:
            raise ConfigurationError("Missing required section: 'output'")

        input_cfg = self.config['input']
        output_cfg = self.config['output']

        # Required input fields
        if 'legitimate_folder' not in input_cfg:
            raise ConfigurationError("Missing required field: input.legitimate_folder")

        if 'covert_folder' not in input_cfg:
            raise ConfigurationError("Missing required field: input.covert_folder")

        # Check paths exist (if validation enabled)
        validation_cfg = self.config.get('validation', {})
        if validation_cfg.get('check_paths_exist', True):
            leg_folder = Path(input_cfg['legitimate_folder'])
            if not leg_folder.exists():
                raise ConfigurationError(
                    f"input.legitimate_folder does not exist: {leg_folder}"
                )

            cov_folder = Path(input_cfg['covert_folder'])
            if not cov_folder.exists():
                raise ConfigurationError(
                    f"input.covert_folder does not exist: {cov_folder}"
                )

        # Required output fields
        if 'results_file' not in output_cfg:
            raise ConfigurationError("Missing required field: output.results_file")

        if 'log_file' not in output_cfg:
            raise ConfigurationError("Missing required field: output.log_file")

    def _validate_logging(self):
        """Validate logging configuration."""
        if 'logging' not in self.config:
            self.logger.warning("No 'logging' section found, using defaults")
            return

        logging_cfg = self.config['logging']

        # level
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR']
        level = logging_cfg.get('level', 'INFO')
        if level not in valid_levels:
            raise ConfigurationError(
                f"logging.level must be one of {valid_levels}, got '{level}'"
            )

        # format
        valid_formats = ['json', 'text']
        log_format = logging_cfg.get('format', 'json')
        if log_format not in valid_formats:
            raise ConfigurationError(
                f"logging.format must be one of {valid_formats}, got '{log_format}'"
            )
