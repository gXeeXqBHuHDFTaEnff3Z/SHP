"""
GAS-LSTM Model Trainer

This module implements training logic for the GAS-LSTM model with early stopping,
learning rate scheduling, and comprehensive training metrics tracking.

Decision References:
    - ADR-0002: GAS-LSTM Training Configuration
    - ADR-0007: Modular Pipeline Architecture (Stage 3: Training)
    - ADR-0010: Reproducibility (deterministic training)

Features:
    - Sliding window sequence generation (X, y pairs)
    - Early stopping with patience
    - Model checkpointing (save best weights)
    - Training history tracking
    - Validation split support
    - GPU acceleration

Usage:
    from src.config_loader import load_config
    from src.logger import setup_logger
    from src.trainer import train_gas_model

    config = load_config("config.yaml")
    logger = setup_logger(config)

    # Train model
    model, history = train_gas_model(
        discrete_windows=train_discrete,
        model=model,
        config=config,
        logger=logger
    )

Author: GASanalysis Team
Date: 2025-10-12
Version: 1.0.0
"""

import sys
import logging
import time
from pathlib import Path
from typing import Tuple, Dict, Any, Optional
import numpy as np
import tensorflow as tf
from tensorflow import keras


# ==============================================================================
# Custom Exceptions
# ==============================================================================

class TrainingError(Exception):
    """Model training failed."""
    pass


# ==============================================================================
# Sequence Generation
# ==============================================================================

def create_sequences(
    discrete_windows: np.ndarray,
    sequence_length: int,
    logger: any
) -> Tuple[np.ndarray, np.ndarray]:
    """
    Create input-output sequence pairs for training.

    This function generates sliding window sequences from discrete state windows.
    Each sequence of length `sequence_length` predicts the next state.

    Args:
        discrete_windows: Discrete state windows, shape (num_windows, window_length)
        sequence_length: Length of input sequences (e.g., 8)
        logger: Logger instance

    Returns:
        Tuple of (X, y):
            X: Input sequences, shape (num_sequences, sequence_length)
            y: Target next states, shape (num_sequences,)

    Decision: ADR-0002 (Next-state prediction task)

    Example:
        >>> X, y = create_sequences(discrete_windows, sequence_length=8, logger=logger)
        >>> print(f"Generated {len(X)} training sequences")
    """
    logger.debug(
        f"Creating sequences: sequence_length={sequence_length}",
        extra={'sequence_length': sequence_length, 'num_windows': len(discrete_windows)}
    )

    X_sequences = []
    y_targets = []

    for window in discrete_windows:
        # Create sliding window sequences
        for i in range(len(window) - sequence_length):
            # Input: sequence_length consecutive states
            X_seq = window[i:i + sequence_length]
            # Target: next state
            y_target = window[i + sequence_length]

            X_sequences.append(X_seq)
            y_targets.append(y_target)

    X = np.array(X_sequences, dtype=np.int32)
    y = np.array(y_targets, dtype=np.int32)

    logger.debug(
        f"Generated {len(X)} sequences",
        extra={'num_sequences': len(X), 'X_shape': X.shape, 'y_shape': y.shape}
    )

    return X, y


# ==============================================================================
# Training Function
# ==============================================================================

def train_gas_model(
    discrete_windows: np.ndarray,
    model: keras.Model,
    config: any,
    logger: any,
    validation_data: Optional[Tuple[np.ndarray, np.ndarray]] = None
) -> Tuple[keras.Model, Dict[str, Any]]:
    """
    Train GAS-LSTM model on discrete state sequences.

    This function:
    1. Generates input-output sequence pairs
    2. Configures early stopping and checkpointing
    3. Trains model with validation monitoring
    4. Returns trained model and training history

    Args:
        discrete_windows: Training discrete windows, shape (num_windows, window_length)
        model: Compiled Keras model from build_gas_lstm_model()
        config: Configuration object
        logger: Logger instance
        validation_data: Optional (X_val, y_val) tuple for validation

    Returns:
        Tuple of (trained_model, history_dict)

    Raises:
        TrainingError: If training fails

    Decision References:
        - ADR-0002: GAS-LSTM training configuration
        - ADR-0010: Reproducibility via deterministic training

    Example:
        >>> model, history = train_gas_model(train_discrete, model, config, logger)
        >>> print(f"Training loss: {history['loss'][-1]:.4f}")
        >>> print(f"Training accuracy: {history['accuracy'][-1]:.4f}")
    """
    start_time = time.time()

    logger.info(
        "Starting model training",
        extra={
            'adr_id': 'ADR-0002',
            'event': 'training_start',
            'num_windows': len(discrete_windows),
            'epochs': config.model.epochs,
            'batch_size': config.model.batch_size
        }
    )

    try:
        # ====================
        # Generate Sequences
        # ====================

        logger.info("Generating training sequences...")
        X_train, y_train = create_sequences(
            discrete_windows,
            config.model.sequence_length,
            logger
        )

        logger.info(
            f"Training set: {len(X_train)} sequences",
            extra={'num_sequences': len(X_train)}
        )

        # ====================
        # Setup Callbacks
        # ====================

        callbacks = []

        # Early Stopping
        early_stopping = keras.callbacks.EarlyStopping(
            monitor='val_loss' if validation_data else 'loss',
            patience=config.model.early_stopping_patience,
            restore_best_weights=config.model.restore_best_weights,
            verbose=1
        )
        callbacks.append(early_stopping)

        logger.debug(
            f"Early stopping configured: patience={config.model.early_stopping_patience}",
            extra={'patience': config.model.early_stopping_patience}
        )

        # Model Checkpoint (save best model)
        if config.model.save_best_model:
            checkpoint_path = config.model.model_save_path.format(length='temp')
            checkpoint_dir = Path(checkpoint_path).parent
            checkpoint_dir.mkdir(parents=True, exist_ok=True)

            model_checkpoint = keras.callbacks.ModelCheckpoint(
                filepath=checkpoint_path,
                monitor='val_loss' if validation_data else 'loss',
                save_best_only=True,
                verbose=0
            )
            callbacks.append(model_checkpoint)

            logger.debug(f"Model checkpointing enabled: {checkpoint_path}")

        # Learning Rate Reduction (optional)
        reduce_lr = keras.callbacks.ReduceLROnPlateau(
            monitor='val_loss' if validation_data else 'loss',
            factor=0.5,
            patience=3,
            min_lr=1e-6,
            verbose=1
        )
        callbacks.append(reduce_lr)

        # ====================
        # Train Model
        # ====================

        logger.info(
            f"Training model: {config.model.epochs} epochs, batch_size={config.model.batch_size}"
        )

        # Determine Keras verbosity from logger level (INFO or lower -> verbose)
        base_logger = getattr(logger, 'logger', logger)
        try:
            log_level = getattr(base_logger, 'level', logging.INFO)
        except Exception:
            log_level = logging.INFO
        keras_verbose = 2 if log_level <= logging.INFO else 0

        history = model.fit(
            X_train,
            y_train,
            epochs=config.model.epochs,
            batch_size=config.model.batch_size,
            validation_split=config.model.validation_split if validation_data is None else 0.0,
            validation_data=validation_data,
            callbacks=callbacks,
            verbose=keras_verbose  # verbose if DEBUG/INFO
        )

        training_time = time.time() - start_time

        # ====================
        # Log Training Results
        # ====================

        final_loss = history.history['loss'][-1]
        final_accuracy = history.history['accuracy'][-1]

        log_data = {
            'adr_id': 'ADR-0002',
            'event': 'training_complete',
            'epochs_completed': len(history.history['loss']),
            'final_loss': round(final_loss, 4),
            'final_accuracy': round(final_accuracy, 4),
            'training_time_sec': round(training_time, 2)
        }

        if validation_data or config.model.validation_split > 0:
            final_val_loss = history.history['val_loss'][-1]
            final_val_accuracy = history.history['val_accuracy'][-1]
            log_data['final_val_loss'] = round(final_val_loss, 4)
            log_data['final_val_accuracy'] = round(final_val_accuracy, 4)

        logger.info(
            f"Training complete: loss={final_loss:.4f}, accuracy={final_accuracy:.4f}",
            extra=log_data
        )

        return model, history.history

    except Exception as e:
        logger.error(
            f"Training failed: {e}",
            extra={'adr_id': 'ADR-0002', 'error': str(e)}
        )
        raise TrainingError(f"Training failed: {e}")


# ==============================================================================
# Batch Training (Multiple Window Lengths)
# ==============================================================================

def train_models_for_all_lengths(
    train_windows_dict: Dict[int, np.ndarray],
    val_windows_dict: Dict[int, np.ndarray],
    config: any,
    logger: any
) -> Dict[int, Tuple[keras.Model, Dict[str, Any]]]:
    """
    Train GAS-LSTM models for multiple window lengths.

    Args:
        train_windows_dict: Dictionary {window_length: discrete_windows}
        val_windows_dict: Dictionary {window_length: discrete_windows}
        config: Configuration object
        logger: Logger instance

    Returns:
        Dictionary {window_length: (model, history)}

    Example:
        >>> results = train_models_for_all_lengths(train_dict, val_dict, config, logger)
        >>> for length, (model, history) in results.items():
        >>>     print(f"L={length}: accuracy={history['accuracy'][-1]:.4f}")
    """
    from src.gas_model import build_gas_lstm_model, compile_gas_lstm_model

    results = {}

    for window_length in sorted(train_windows_dict.keys()):
        logger.info(f"\n{'='*70}")
        logger.info(f"Training model for window length: {window_length}")
        logger.info(f"{'='*70}")

        try:
            # Build model
            model = build_gas_lstm_model(
                sequence_length=config.model.sequence_length,
                num_states=config.model.output_states,
                config=config,
                logger=logger
            )

            # Compile model
            model = compile_gas_lstm_model(model, config, logger)

            # Prepare validation data
            val_data = None
            if window_length in val_windows_dict:
                X_val, y_val = create_sequences(
                    val_windows_dict[window_length],
                    config.model.sequence_length,
                    logger
                )
                val_data = (X_val, y_val)

            # Train model
            model, history = train_gas_model(
                discrete_windows=train_windows_dict[window_length],
                model=model,
                config=config,
                logger=logger,
                validation_data=val_data
            )

            # Save model
            save_path = config.model.model_save_path.format(length=window_length)
            from src.gas_model import save_gas_lstm_model
            save_gas_lstm_model(model, save_path, config, logger)

            results[window_length] = (model, history)

        except Exception as e:
            logger.error(
                f"Failed to train model for L={window_length}: {e}",
                extra={'window_length': window_length, 'error': str(e)}
            )

    return results


# ==============================================================================
# Training Utilities
# ==============================================================================

def plot_training_history(
    history: Dict[str, Any],
    save_path: Optional[str] = None,
    logger: Optional[any] = None
):
    """
    Plot training history (loss and accuracy curves).

    Args:
        history: Training history dictionary from model.fit()
        save_path: Optional path to save plot
        logger: Optional logger instance

    Example:
        >>> plot_training_history(history, "results/training_history.png", logger)
    """
    import matplotlib.pyplot as plt

    fig, axes = plt.subplots(1, 2, figsize=(12, 4))

    # Loss plot
    axes[0].plot(history['loss'], label='Training Loss')
    if 'val_loss' in history:
        axes[0].plot(history['val_loss'], label='Validation Loss')
    axes[0].set_xlabel('Epoch')
    axes[0].set_ylabel('Loss')
    axes[0].set_title('Training and Validation Loss')
    axes[0].legend()
    axes[0].grid(True, alpha=0.3)

    # Accuracy plot
    axes[1].plot(history['accuracy'], label='Training Accuracy')
    if 'val_accuracy' in history:
        axes[1].plot(history['val_accuracy'], label='Validation Accuracy')
    axes[1].set_xlabel('Epoch')
    axes[1].set_ylabel('Accuracy')
    axes[1].set_title('Training and Validation Accuracy')
    axes[1].legend()
    axes[1].grid(True, alpha=0.3)

    plt.tight_layout()

    if save_path:
        Path(save_path).parent.mkdir(parents=True, exist_ok=True)
        plt.savefig(save_path, dpi=150, bbox_inches='tight')
        if logger:
            logger.info(f"Saved training history plot: {save_path}")
    else:
        plt.show()

    plt.close()


# ==============================================================================
# CLI Entry Point (for testing)
# ==============================================================================

if __name__ == "__main__":
    """
    Standalone testing mode.

    Usage:
        python src/trainer.py <train_npz_path>
    """
    import sys
    from pathlib import Path

    # Add parent directory to path
    sys.path.insert(0, str(Path(__file__).parent.parent))

    from src.config_loader import load_config
    from src.logger import setup_logger
    from src.windowing import load_windows_from_npz
    from src.discretizer import IPDDiscretizer
    from src.gas_model import build_gas_lstm_model, compile_gas_lstm_model, configure_gpu, set_random_seeds

    print("Testing trainer module...\n")
    print("=" * 70)

    # Load configuration
    try:
        config = load_config("config.yaml")
        logger = setup_logger(config, name="TrainerTest")
    except Exception as e:
        print(f"Error loading config/logger: {e}")
        sys.exit(1)

    # Configure GPU and seeds
    configure_gpu(config, logger)
    set_random_seeds(config.project.random_seed, logger)

    # Check arguments
    if len(sys.argv) < 2:
        print("Usage: python src/trainer.py <train_npz_path>")
        print("\nExample:")
        print("  python src/trainer.py data/windows/train_L200.npz")
        sys.exit(1)

    npz_path = sys.argv[1]

    # Test training
    try:
        print(f"\nLoading windows from: {npz_path}\n")
        windows, labels, metadata = load_windows_from_npz(npz_path, logger)

        print(f"Loaded {len(windows)} windows\n")

        # Discretize
        print("Discretizing windows...")
        discretizer = IPDDiscretizer(config, logger)
        discrete_windows = discretizer.fit_transform(windows)

        print(f"Discrete windows shape: {discrete_windows.shape}\n")

        # Build model
        print("Building model...")
        model = build_gas_lstm_model(
            sequence_length=config.model.sequence_length,
            num_states=config.model.output_states,
            config=config,
            logger=logger
        )
        model = compile_gas_lstm_model(model, config, logger)

        # Train model (with reduced epochs for testing)
        print("\nTraining model (5 epochs for testing)...\n")
        config.model.epochs = 5
        model, history = train_gas_model(discrete_windows, model, config, logger)

        print("\n" + "=" * 70)
        print("TRAINING SUMMARY")
        print("=" * 70)
        print(f"Epochs:         {len(history['loss'])}")
        print(f"Final loss:     {history['loss'][-1]:.4f}")
        print(f"Final accuracy: {history['accuracy'][-1]:.4f}")
        print("=" * 70)

        # Plot history
        print("\nPlotting training history...")
        plot_training_history(history, "test_training_history.png", logger)

    except Exception as e:
        print(f"\nTraining test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    print("\n" + "=" * 70)
    print("Trainer testing complete!")
    print("=" * 70)
