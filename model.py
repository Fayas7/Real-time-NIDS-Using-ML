import pandas as pd
import numpy as np
import xgboost as xgb
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score
import joblib
import logging
import os
import json
from sklearn.model_selection import train_test_split

def create_model(params=None):
    """
    Create and return an XGBoost classifier with specified parameters.
    
    Args:
        params (dict, optional): Parameters for XGBoost. Defaults to None.
        
    Returns:
        xgb.XGBClassifier: An initialized XGBoost model
    """
    # Default parameters if none provided
    if params is None:
        params = {
            'n_estimators': 100,
            'learning_rate': 0.1,
            'max_depth': 5,
            'min_child_weight': 1,
            'subsample': 0.8,
            'colsample_bytree': 0.8,
            'objective': 'multi:softprob',
            'random_state': 42
        }
    
    # Initialize and return the model
    return xgb.XGBClassifier(**params)

def train_and_save_model(X_train, y_train, model_dir='models', params=None, model_name='xgboost_nids'):
    """
    Train an XGBoost model and save it to disk.
    
    Args:
        X_train (DataFrame/ndarray): Training features
        y_train (Series/ndarray): Training labels
        model_dir (str): Directory to save the model
        params (dict, optional): Model parameters
        model_name (str): Base name for the model files
        
    Returns:
        tuple: (trained_model, feature_importance_dict)
    """
    # Create model
    model = create_model(params)
    
    # Train the model
    logging.info("Training XGBoost model...")
    model.fit(X_train, y_train)
    logging.info("Model training completed successfully")
    
    # Create directory if it doesn't exist
    os.makedirs(model_dir, exist_ok=True)
    
    # Save model
    model_path = os.path.join(model_dir, f"{model_name}.joblib")
    joblib.dump(model, model_path)
    logging.info(f"Model saved to {model_path}")
    
    # Save feature importances
    if hasattr(model, 'feature_importances_'):
        feature_importances = model.feature_importances_
        if hasattr(X_train, 'columns'):
            # If X_train is a DataFrame with column names
            features = X_train.columns
            importance_dict = {feature: float(importance) for feature, importance in zip(features, feature_importances)}
        else:
            # If X_train doesn't have column names
            importance_dict = {f"feature_{i}": float(importance) for i, importance in enumerate(feature_importances)}
        
        # Save feature importances to JSON
        importance_path = os.path.join(model_dir, f"{model_name}_feature_importance.json")
        with open(importance_path, 'w') as f:
            json.dump(importance_dict, f, indent=4)
        logging.info(f"Feature importances saved to {importance_path}")
        
        return model, importance_dict
    
    return model, None

def load_model(model_path):
    """
    Load a model from disk.
    
    Args:
        model_path (str): Path to the saved model
        
    Returns:
        The loaded model
    """
    try:
        model = joblib.load(model_path)
        logging.info(f"Model loaded successfully from {model_path}")
        return model
    except Exception as e:
        logging.error(f"Error loading model from {model_path}: {e}")
        raise

def evaluate_model(model, X_test, y_test, class_names=None):
    """
    Evaluate a model on test data.
    
    Args:
        model: The trained model
        X_test (DataFrame/ndarray): Test features
        y_test (Series/ndarray): Test labels
        class_names (list, optional): Names of the classes
        
    Returns:
        dict: Dictionary containing evaluation metrics
    """
    try:
        # Make predictions
        y_pred = model.predict(X_test)
        
        # Calculate metrics
        accuracy = accuracy_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred, average='weighted')
        
        # Generate confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        
        # Generate classification report
        if class_names is not None:
            report = classification_report(y_test, y_pred, target_names=class_names, output_dict=True)
        else:
            report = classification_report(y_test, y_pred, output_dict=True)
        
        # Log results
        logging.info(f"Model Accuracy: {accuracy:.4f}")
        logging.info(f"Weighted F1 Score: {f1:.4f}")
        logging.info(f"Confusion Matrix:\n{cm}")
        logging.info(f"Classification Report:\n{classification_report(y_test, y_pred, target_names=class_names)}")
        
        # Return metrics as a dictionary
        metrics = {
            'accuracy': float(accuracy),
            'f1_score': float(f1),
            'confusion_matrix': cm.tolist(),
            'classification_report': report
        }
        
        return metrics
    
    except Exception as e:
        logging.error(f"Error during model evaluation: {e}")
        raise

def predict_intrusion(model, data, threshold=0.5):
    """
    Predict network intrusions on new data.
    
    Args:
        model: Trained model
        data (DataFrame): Data to predict on
        threshold (float): Probability threshold for binary classification
        
    Returns:
        DataFrame: Original data with prediction results added
    """
    try:
        # Make raw predictions
        if hasattr(model, 'predict_proba'):
            # Get probability predictions if available
            probas = model.predict_proba(data)
            predictions = model.predict(data)
            
            # Create results DataFrame
            results = data.copy()
            results['prediction'] = predictions
            
            # Add probability columns for each class
            if probas.shape[1] > 2:  # Multiclass case
                for i, col_name in enumerate(model.classes_):
                    results[f'prob_{col_name}'] = probas[:, i]
            else:  # Binary case
                results['probability'] = probas[:, 1]
                results['is_intrusion'] = results['probability'] > threshold
        else:
            # Just use predict if predict_proba is not available
            predictions = model.predict(data)
            results = data.copy()
            results['prediction'] = predictions
            results['is_intrusion'] = predictions != 0  # Assuming 0 is the normal class
        
        logging.info(f"Predictions generated for {len(data)} samples")
        return results
    
    except Exception as e:
        logging.error(f"Error during prediction: {e}")
        raise

def cross_validate_model(X, y, params=None, n_splits=5):
    """
    Perform cross-validation on the model.
    
    Args:
        X (DataFrame/ndarray): Features
        y (Series/ndarray): Target labels
        params (dict, optional): Model parameters
        n_splits (int): Number of cross-validation folds
        
    Returns:
        dict: Cross-validation results
    """
    from sklearn.model_selection import cross_val_score, KFold
    
    # Create model
    model = create_model(params)
    
    # Set up K-fold cross-validation
    kfold = KFold(n_splits=n_splits, shuffle=True, random_state=42)
    
    # Perform cross-validation
    logging.info(f"Performing {n_splits}-fold cross-validation...")
    cv_accuracy = cross_val_score(model, X, y, cv=kfold, scoring='accuracy')
    cv_f1 = cross_val_score(model, X, y, cv=kfold, scoring='f1_weighted')
    
    # Log results
    logging.info(f"Cross-validation accuracy: {cv_accuracy.mean():.4f} ± {cv_accuracy.std():.4f}")
    logging.info(f"Cross-validation F1 score: {cv_f1.mean():.4f} ± {cv_f1.std():.4f}")
    
    # Return results
    return {
        'cv_accuracy_mean': float(cv_accuracy.mean()),
        'cv_accuracy_std': float(cv_accuracy.std()),
        'cv_f1_mean': float(cv_f1.mean()),
        'cv_f1_std': float(cv_f1.std()),
        'cv_accuracy_all': cv_accuracy.tolist(),
        'cv_f1_all': cv_f1.tolist()
    }

def save_performance_metrics(metrics, model_dir='models', filename='model_performance.json'):
    """
    Save model performance metrics to a JSON file.
    
    Args:
        metrics (dict): Dictionary of metrics
        model_dir (str): Directory to save the metrics
        filename (str): Name of the JSON file
    """
    os.makedirs(model_dir, exist_ok=True)
    metrics_path = os.path.join(model_dir, filename)
    
    with open(metrics_path, 'w') as f:
        json.dump(metrics, f, indent=4)
    
    logging.info(f"Performance metrics saved to {metrics_path}")

# If the script is run directly, perform a simple test
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # Simple test with randomly generated data
    logging.info("Generating test data...")
    X = np.random.rand(1000, 10)
    y = np.random.randint(0, 3, 1000)  # 3 classes
    
    # Split the data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Train and evaluate
    logging.info("Training test model...")
    model, _ = train_and_save_model(X_train, y_train, model_dir='test_models')
    
    logging.info("Evaluating test model...")
    metrics = evaluate_model(model, X_test, y_test)
    
    # Save metrics
    save_performance_metrics(metrics, model_dir='test_models')
    
    logging.info("Test completed successfully")