# model.py

import pandas as pd
import xgboost as xgb
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder
from imblearn.over_sampling import SMOTE
from utils import save_model, load_model

def load_data():
    """Load the preprocessed training data and encode labels."""
    # Load the data
    X_train = pd.read_csv("C:/Users/fayaz/Documents/NIDS_IMPLEMENTATION/data/X_train_processed.csv")
    y_train = pd.read_csv("C:/Users/fayaz/Documents/NIDS_IMPLEMENTATION/data/y_train_processed.csv").values.ravel()  # Flatten the array

    # Encode string labels to numeric values
    label_encoder = LabelEncoder()
    y_train_encoded = label_encoder.fit_transform(y_train)

    # Check the class distribution after loading the data
    print("Class distribution after loading data:", pd.Series(y_train_encoded).value_counts())

    # Apply SMOTE to balance the classes
    smote = SMOTE(random_state=42, k_neighbors=2)  # Adjust k_neighbors as needed
    X_train_resampled, y_train_resampled = smote.fit_resample(X_train, y_train_encoded)

    print("Class distribution after SMOTE:", pd.Series(y_train_resampled).value_counts())

    return X_train_resampled, y_train_resampled, label_encoder
    

def train_model():
    """Train the machine learning model using XGBoost."""
    # Load your data
    X_train, y_train, label_encoder = load_data()

    # Initialize the XGBoost model
    model = xgb.XGBClassifier(
        n_estimators=100,          # Number of trees
        learning_rate=0.1,         # Step size shrinkage
        max_depth=3,               # Maximum depth of a tree
        random_state=42            # For reproducibility
    )

    # Train the model
    model.fit(X_train, y_train)

    # Save the model and the label encoder
    save_model(model, "model.joblib")
    save_model(label_encoder, "label_encoder.joblib")  # Save the label encoder for later use

    print("Model trained and saved successfully.")

def evaluate_model():
    """Evaluate the model on the test dataset."""
    # Load your test data
    X_test = pd.read_csv("C:/Users/fayaz/Documents/NIDS_IMPLEMENTATION/data/X_test_processed.csv")
    y_test = pd.read_csv("C:/Users/fayaz/Documents/NIDS_IMPLEMENTATION/data/y_test_processed.csv").values.ravel()

    # Load the trained model and the label encoder
    model = load_model("model.joblib")
    label_encoder = load_model("label_encoder.joblib")

    # Encode the test labels
    y_test_encoded = label_encoder.transform(y_test)

    # Make predictions
    y_pred = model.predict(X_test)

    # Print evaluation metrics
    print(confusion_matrix(y_test_encoded, y_pred))
    print(classification_report(y_test_encoded, y_pred))