"""
GAS-LSTM Model Architecture

This module implements the Grammar-Aware Symbolic (GAS) LSTM model for time
series anomaly detection in network traffic. The model uses an Embedding layer
to capture state semantics, followed by LSTM for temporal modeling and a Dense
output layer for next-state prediction.

Decision References:
    - ADR-0002: GAS-LSTM Architecture (Embedding→LSTM→Dense)
    - ADR-0007: Modular Pipeline Architecture (Stage 3: GAS Analysis)
    - ADR-0010: Reproducibility (deterministic model initialization)

Architecture:
    Input: Discrete state sequences, shape (batch_size, sequence_length)
    ↓
    Embedding: State → Dense vector, dim=100
    ↓
    LSTM: Temporal modeling, units=64, dropout=0.2
    ↓
    Dense: Next-state prediction, softmax over 16 states
    ↓
    Output: Probability distribution, shape (batch_size, 16)

Total parameters: ~44,880 (embedding=1,600, lstm=42,240, dense=1,040)

Usage:
    from src.config_loader import load_config
    from src.logger import setup_logger
    from src.gas_model import build_gas_lstm_model

    config = load_config("config.yaml")
    logger = setup_logger(config)

    # Build model
    model = build_gas_lstm_model(
        sequence_length=8,
        num_states=16,
        config=config,
        logger=logger
    )

    # Compile model
    model.compile(
        optimizer='adam',
        loss='sparse_categorical_crossentropy',
        metrics=['accuracy']
    )

    # Summary
    model.summary()

Author: GASanalysis Team
Date: 2025-10-12
Version: 1.0.0
"""

import sys
import numpy as np
from pathlib import Path
from typing import Optional, Tuple
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers, models


# ==============================================================================
# Custom Exceptions
# ==============================================================================

class ModelError(Exception):
    """Model construction or operation failed."""
    pass


# ==============================================================================
# GPU Configuration
# ==============================================================================

def configure_gpu(config: any, logger: any):
    """
    Configure GPU settings for TensorFlow.

    Args:
        config: Configuration object
        logger: Logger instance

    Decision: ADR-0002 (GPU acceleration for training efficiency)
    """
    if config.performance.gpu_enabled:
        gpus = tf.config.list_physical_devices('GPU')

        if gpus:
            try:
                # Enable memory growth (prevents TF from allocating all GPU memory)
                if config.performance.gpu_memory_growth:
                    for gpu in gpus:
                        tf.config.experimental.set_memory_growth(gpu, True)

                logger.info(
                    f"GPU configured: {len(gpus)} device(s) available",
                    extra={
                        'adr_id': 'ADR-0002',
                        'event': 'gpu_configured',
                        'num_gpus': len(gpus),
                        'memory_growth': config.performance.gpu_memory_growth
                    }
                )

            except RuntimeError as e:
                logger.warning(f"GPU configuration failed: {e}")
        else:
            logger.warning("GPU requested but none available, using CPU")
    else:
        # Disable GPU
        tf.config.set_visible_devices([], 'GPU')
        logger.info("GPU disabled, using CPU only")


def set_random_seeds(seed: int, logger: any):
    """
    Set random seeds for reproducibility.

    Args:
        seed: Random seed value
        logger: Logger instance

    Decision: ADR-0010 (Reproducibility via deterministic seeds)
    """
    np.random.seed(seed)
    tf.random.set_seed(seed)

    logger.info(
        f"Random seeds set: {seed}",
        extra={'adr_id': 'ADR-0010', 'seed': seed}
    )


# ==============================================================================
# GAS-LSTM Model Builder
# ==============================================================================

def build_gas_lstm_model(
    sequence_length: int,
    num_states: int,
    config: any,
    logger: any
) -> keras.Model:
    """
    Build GAS-LSTM model for time series anomaly detection.

    Architecture:
        1. Embedding layer: Maps discrete states to dense vectors
        2. LSTM layer: Captures temporal dependencies
        3. Dense output layer: Predicts next state (softmax)

    Args:
        sequence_length: Length of input sequences (e.g., 8)
        num_states: Number of discrete states (e.g., 16)
        config: Configuration object from config_loader
        logger: Logger instance from setup_logger

    Returns:
        Compiled Keras model

    Raises:
        ModelError: If model construction fails

    Decision References:
        - ADR-0002: GAS-LSTM architecture specification
        - ADR-0007: Modular pipeline design

    Example:
        >>> model = build_gas_lstm_model(8, 16, config, logger)
        >>> model.summary()
        >>> # Total params: ~44,880
    """
    logger.info(
        "Building GAS-LSTM model",
        extra={
            'adr_id': 'ADR-0002',
            'event': 'model_build_start',
            'sequence_length': sequence_length,
            'num_states': num_states
        }
    )

    try:
        # ====================
        # Input Layer
        # ====================

        input_layer = layers.Input(
            shape=(sequence_length,),
            dtype=tf.int32,
            name='state_sequence_input'
        )

        logger.debug(
            f"Input layer: shape=(None, {sequence_length})",
            extra={'layer': 'input', 'shape': (sequence_length,)}
        )

        # ====================
        # Embedding Layer
        # ====================

        embedding_dim = config.model.embedding_dim

        embedding_layer = layers.Embedding(
            input_dim=num_states,  # Vocabulary size
            output_dim=embedding_dim,  # Dense vector dimension
            input_length=sequence_length,
            embeddings_initializer='glorot_uniform',
            name='state_embedding'
        )(input_layer)

        logger.debug(
            f"Embedding layer: {num_states} states → {embedding_dim}D vectors",
            extra={
                'layer': 'embedding',
                'input_dim': num_states,
                'output_dim': embedding_dim,
                'params': num_states * embedding_dim
            }
        )

        # ====================
        # LSTM Layer
        # ====================

        lstm_units = config.model.lstm_units

        lstm_layer = layers.LSTM(
            units=lstm_units,
            return_sequences=False,  # Return only last output
            dropout=0.2,  # Dropout for regularization
            recurrent_dropout=0.2,
            kernel_initializer='glorot_uniform',
            name='lstm_temporal'
        )(embedding_layer)

        logger.debug(
            f"LSTM layer: {lstm_units} units (with dropout=0.2)",
            extra={
                'layer': 'lstm',
                'units': lstm_units,
                'dropout': 0.2,
                'params': 4 * lstm_units * (embedding_dim + lstm_units + 1)  # Approximate
            }
        )

        # ====================
        # Output Layer (Dense)
        # ====================

        output_layer = layers.Dense(
            units=num_states,  # Predict next state (one of num_states options)
            activation='softmax',
            kernel_initializer='glorot_uniform',
            name='next_state_prediction'
        )(lstm_layer)

        logger.debug(
            f"Output layer: softmax over {num_states} states",
            extra={
                'layer': 'dense_output',
                'units': num_states,
                'activation': 'softmax',
                'params': lstm_units * num_states + num_states
            }
        )

        # ====================
        # Build Model
        # ====================

        model = models.Model(
            inputs=input_layer,
            outputs=output_layer,
            name='GAS_LSTM'
        )

        # Count total parameters
        total_params = model.count_params()

        logger.info(
            "GAS-LSTM model built successfully",
            extra={
                'adr_id': 'ADR-0002',
                'event': 'model_build_complete',
                'architecture': 'Embedding→LSTM→Dense',
                'total_params': total_params,
                'sequence_length': sequence_length,
                'num_states': num_states,
                'embedding_dim': embedding_dim,
                'lstm_units': lstm_units
            }
        )

        return model

    except Exception as e:
        logger.error(
            f"Failed to build model: {e}",
            extra={'adr_id': 'ADR-0002', 'error': str(e)}
        )
        raise ModelError(f"Failed to build model: {e}")


def compile_gas_lstm_model(
    model: keras.Model,
    config: any,
    logger: any
) -> keras.Model:
    """
    Compile GAS-LSTM model with optimizer and loss function.

    Args:
        model: Keras model from build_gas_lstm_model()
        config: Configuration object
        logger: Logger instance

    Returns:
        Compiled model

    Decision: ADR-0002 (Adam optimizer, sparse categorical crossentropy)

    Example:
        >>> model = build_gas_lstm_model(8, 16, config, logger)
        >>> model = compile_gas_lstm_model(model, config, logger)
    """
    logger.info(
        "Compiling GAS-LSTM model",
        extra={
            'adr_id': 'ADR-0002',
            'optimizer': config.model.optimizer,
            'loss': config.model.loss,
            'learning_rate': config.model.learning_rate
        }
    )

    try:
        # Create optimizer with learning rate
        if config.model.optimizer.lower() == 'adam':
            optimizer = keras.optimizers.Adam(learning_rate=config.model.learning_rate)
        elif config.model.optimizer.lower() == 'sgd':
            optimizer = keras.optimizers.SGD(learning_rate=config.model.learning_rate)
        elif config.model.optimizer.lower() == 'rmsprop':
            optimizer = keras.optimizers.RMSprop(learning_rate=config.model.learning_rate)
        else:
            optimizer = config.model.optimizer  # Use string name

        # Compile model
        model.compile(
            optimizer=optimizer,
            loss=config.model.loss,
            metrics=['accuracy', 'sparse_categorical_crossentropy']
        )

        logger.info(
            "Model compilation complete",
            extra={
                'adr_id': 'ADR-0002',
                'event': 'model_compiled',
                'optimizer': config.model.optimizer,
                'learning_rate': config.model.learning_rate
            }
        )

        return model

    except Exception as e:
        logger.error(
            f"Failed to compile model: {e}",
            extra={'error': str(e)}
        )
        raise ModelError(f"Failed to compile model: {e}")


# ==============================================================================
# Model Summary and Visualization
# ==============================================================================

def get_model_summary(model: keras.Model) -> str:
    """
    Get model summary as string.

    Args:
        model: Keras model

    Returns:
        Model summary string

    Example:
        >>> summary = get_model_summary(model)
        >>> print(summary)
    """
    from io import StringIO
    stream = StringIO()
    model.summary(print_fn=lambda x: stream.write(x + '\n'))
    return stream.getvalue()


def save_model_architecture(model: keras.Model, filepath: str, logger: any):
    """
    Save model architecture diagram to file.

    Args:
        model: Keras model
        filepath: Path to save diagram (PNG format)
        logger: Logger instance

    Example:
        >>> save_model_architecture(model, "results/models/gas_lstm_architecture.png", logger)
    """
    filepath_obj = Path(filepath)
    filepath_obj.parent.mkdir(parents=True, exist_ok=True)

    try:
        keras.utils.plot_model(
            model,
            to_file=str(filepath_obj),
            show_shapes=True,
            show_layer_names=True,
            rankdir='TB',  # Top to bottom
            expand_nested=False,
            dpi=150
        )

        logger.info(
            f"Saved model architecture diagram: {filepath_obj.name}",
            extra={'filepath': str(filepath_obj)}
        )

    except Exception as e:
        logger.warning(
            f"Failed to save architecture diagram: {e}",
            extra={'filepath': str(filepath_obj), 'error': str(e)}
        )


# ==============================================================================
# Model Save/Load
# ==============================================================================

def save_gas_lstm_model(model: keras.Model, filepath: str, config: any, logger: any):
    """
    Save trained model to file.

    Args:
        model: Trained Keras model
        filepath: Path to save model (HDF5 format)
        config: Configuration object
        logger: Logger instance

    Decision: ADR-0010 (Save models for reproducibility)

    Example:
        >>> save_gas_lstm_model(model, "results/models/gas_lstm_L200.h5", config, logger)
    """
    filepath_obj = Path(filepath)
    filepath_obj.parent.mkdir(parents=True, exist_ok=True)

    try:
        model.save(str(filepath_obj))

        file_size_mb = filepath_obj.stat().st_size / (1024 ** 2)

        logger.info(
            f"Saved model to {filepath_obj.name}",
            extra={
                'adr_id': 'ADR-0010',
                'event': 'model_saved',
                'filepath': str(filepath_obj),
                'file_size_mb': round(file_size_mb, 2)
            }
        )

    except Exception as e:
        logger.error(
            f"Failed to save model: {e}",
            extra={'filepath': str(filepath_obj), 'error': str(e)}
        )
        raise ModelError(f"Failed to save model: {e}")


def load_gas_lstm_model(filepath: str, logger: any) -> keras.Model:
    """
    Load trained model from file.

    Args:
        filepath: Path to saved model (HDF5 format)
        logger: Logger instance

    Returns:
        Loaded Keras model

    Example:
        >>> model = load_gas_lstm_model("results/models/gas_lstm_L200.h5", logger)
    """
    filepath_obj = Path(filepath)

    try:
        model = keras.models.load_model(str(filepath_obj))

        logger.info(
            f"Loaded model from {filepath_obj.name}",
            extra={
                'adr_id': 'ADR-0010',
                'event': 'model_loaded',
                'filepath': str(filepath_obj),
                'total_params': model.count_params()
            }
        )

        return model

    except Exception as e:
        logger.error(
            f"Failed to load model: {e}",
            extra={'filepath': str(filepath_obj), 'error': str(e)}
        )
        raise ModelError(f"Failed to load model: {e}")


# ==============================================================================
# CLI Entry Point (for testing)
# ==============================================================================

if __name__ == "__main__":
    """
    Standalone testing mode.

    Usage:
        python src/gas_model.py
    """
    import sys
    from pathlib import Path

    # Add parent directory to path
    sys.path.insert(0, str(Path(__file__).parent.parent))

    from src.config_loader import load_config
    from src.logger import setup_logger

    print("Testing GAS-LSTM model module...\n")
    print("=" * 70)

    # Load configuration
    try:
        config = load_config("config.yaml")
        logger = setup_logger(config, name="GASModelTest")
    except Exception as e:
        print(f"Error loading config/logger: {e}")
        sys.exit(1)

    # Configure GPU
    configure_gpu(config, logger)
    set_random_seeds(config.project.random_seed, logger)

    # Build model
    try:
        print("\nBuilding GAS-LSTM model...\n")

        model = build_gas_lstm_model(
            sequence_length=config.model.sequence_length,
            num_states=config.model.output_states,
            config=config,
            logger=logger
        )

        # Compile model
        model = compile_gas_lstm_model(model, config, logger)

        print("\n" + "=" * 70)
        print("MODEL SUMMARY")
        print("=" * 70)
        model.summary()
        print("=" * 70)

        # Test model with dummy data
        print("\nTesting model with dummy data...")
        batch_size = 32
        dummy_input = np.random.randint(0, config.model.output_states, size=(batch_size, config.model.sequence_length))
        predictions = model.predict(dummy_input, verbose=0)

        print(f"Input shape:       {dummy_input.shape}")
        print(f"Output shape:      {predictions.shape}")
        print(f"Output range:      [{predictions.min():.4f}, {predictions.max():.4f}]")
        print(f"Sample prediction: {predictions[0, :5]}")

        # Save model
        print("\nSaving model...")
        save_gas_lstm_model(model, "test_gas_lstm_model.h5", config, logger)

        # Load model
        print("Loading model...")
        model_loaded = load_gas_lstm_model("test_gas_lstm_model.h5", logger)
        print(f"Loaded model params: {model_loaded.count_params()}")

    except Exception as e:
        print(f"\nModel testing failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    print("\n" + "=" * 70)
    print("GAS-LSTM model testing complete!")
    print("=" * 70)
