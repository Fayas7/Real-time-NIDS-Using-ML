# utils.py

import joblib
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)

def save_model(model, file_path):
    """Save the trained model to a file."""
    joblib.dump(model, file_path)
    logging.info(f"Model saved to {file_path}")

def load_model(file_path):
    """Load a trained model from a file."""
    model = joblib.load(file_path)
    logging.info(f"Model loaded from {file_path}")
    return model