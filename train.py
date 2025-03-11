import pandas as pd
import numpy as np
import logging
import os
import joblib
from sklearn.preprocessing import LabelEncoder
import xgboost as xgb
from sklearn.model_selection import GridSearchCV

def load_processed_data():
    """
    Load preprocessed data from disk if available.
    
    Returns:
        tuple: X_train, y_train for model training
    """
    try:
        # Check if processed data exists
        if (os.path.exists('data/processed/X_train_balanced.csv') and 
            os.path.exists('data/processed/y_train_balanced.csv')):
            # Load balanced data if available
            X_train = pd.read_csv('data/processed/X_train_balanced.csv')
            y_train = pd.read_csv('data/processed/y_train_balanced.csv').values.ravel()
            logging.info(f"Loaded balanced training data with {X_train.shape[0]} samples")
        elif (os.path.exists('data/processed/X_train.csv') and 
              os.path.exists('data/processed/y_train.csv')):
            # Load unbalanced data if balanced not available
            X_train = pd.read_csv('data/processed/X_train.csv')
            y_train = pd.read_csv('data/processed/y_train.csv').values.ravel()
            logging.info(f"Loaded unbalanced training data with {X_train.shape[0]} samples")
        else:
            raise FileNotFoundError("Processed training data not found")
            
        return X_train, y_train
        
    except Exception as e:
        logging.error(f"Error loading processed data: {e}")
        raise

def train_model(X_train=None, y_train=None, tune_hyperparameters=False):
    """
    Train an XGBoost model for network intrusion detection.
    
    Args:
        X_train: Feature matrix for training (optional, will load from disk if not provided)
        y_train: Target labels for training (optional, will load from disk if not provided)
        tune_hyperparameters (bool): Whether to tune hyperparameters using GridSearchCV
        
    Returns:
        tuple: Trained model and label encoder
    """
    try:
        # Load data if not provided
        if X_train is None or y_train is None:
            X_train, y_train = load_processed_data()
        
        # Encode labels if they're not already numeric
        if not pd.api.types.is_numeric_dtype(y_train):
            logging.info("Encoding non-numeric target labels...")
            label_encoder = LabelEncoder()
            y_train_encoded = label_encoder.fit_transform(y_train)
        else:
            logging.info("Target labels are already numeric")
            # Create a dummy encoder that just returns the input
            label_encoder = LabelEncoder()
            label_encoder.classes_ = np.unique(y_train)
            y_train_encoded = y_train
        
        # Log class distribution
        class_distribution = pd.Series(y_train_encoded).value_counts().sort_index()
        logging.info(f"Training class distribution:\n{class_distribution}")
        
        if tune_hyperparameters:
            logging.info("Performing hyperparameter tuning...")
            
            # Define parameter grid
            param_grid = {
                'n_estimators': [50, 100, 200],
                'max_depth': [3, 4, 5],
                'learning_rate': [0.01, 0.1, 0.2],
                'subsample': [0.8, 1.0],
                'colsample_bytree': [0.8, 1.0]
            }
            
            # Initialize XGBoost classifier
            xgb_model = xgb.XGBClassifier(
                objective='multi:softprob' if len(np.unique(y_train_encoded)) > 2 else 'binary:logistic',
                random_state=42,
                n_jobs=-1  # Use all available cores
            )
            
            # Set up GridSearchCV
            grid_search = GridSearchCV(
                estimator=xgb_model,
                param_grid=param_grid,
                cv=3,  # Number of cross-validation folds
                scoring='f1_weighted',  # Metric to optimize
                verbose=1,
                n_jobs=-1  # Use all available cores
            )
            
            # Fit GridSearchCV
            grid_search.fit(X_train, y_train_encoded)
            
            # Get best parameters
            best_params = grid_search.best_params_
            logging.info(f"Best parameters found: {best_params}")
            
            # Train model with best parameters
            model = xgb.XGBClassifier(
                objective='multi:softprob' if len(np.unique(y_train_encoded)) > 2 else 'binary:logistic',
                random_state=42,
                **best_params
            )
            
        else:
            logging.info("Training XGBoost model with default parameters...")
            
            # Initialize model with default parameters
            model = xgb.XGBClassifier(
                n_estimators=100,
                learning_rate=0.1,
                max_depth=4,
                subsample=0.8,
                colsample_bytree=0.8,
                objective='multi:softprob' if len(np.unique(y_train_encoded)) > 2 else 'binary:logistic',
                random_state=42
            )
        
        # Train the model
        model.fit(
            X_train, 
            y_train_encoded,
            eval_metric=['merror', 'mlogloss'] if len(np.unique(y_train_encoded)) > 2 else ['error', 'logloss'],
            verbose=True
        )
        
        logging.info("Model training completed")
        
        # Save the model and label encoder
        os.makedirs('models', exist_ok=True)
        joblib.dump(model, 'models/xgboost_model.joblib')
        joblib.dump(label_encoder, 'models/label_encoder.joblib')
        
        logging.info("Model and label encoder saved to models/ directory")
        
        # Feature importance analysis
        if hasattr(model, 'feature_importances_'):
            feature_importances = model.feature_importances_
            feature_names = X_train.columns if isinstance(X_train, pd.DataFrame) else [f"feature_{i}" for i in range(X_train.shape[1])]
            
            # Create DataFrame for feature importances
            importance_df = pd.DataFrame({
                'Feature': feature_names,
                'Importance': feature_importances
            }).sort_values('Importance', ascending=False)
            
            # Save feature importances
            importance_df.to_csv('results/feature_importances.csv', index=False)
            
            # Log top 10 important features
            logging.info(f"Top 10 important features:\n{importance_df.head(10)}")
        
        return model, label_encoder
        
    except Exception as e:
        logging.error(f"Error in model training: {e}")
        import traceback
        logging.error(traceback.format_exc())
        raise