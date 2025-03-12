import pandas as pd
import numpy as np
import time
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_recall_fscore_support
from xgboost import XGBClassifier
import os

# Create directory for saving plots
os.makedirs(r'C:\Users\fayaz\Documents\NIDS_IMPLEMENTATION\results\plots', exist_ok=True)

# Load preprocessed data
print("Loading preprocessed data...")
train_data = pd.read_csv(r'C:\Users\fayaz\Documents\NIDS_IMPLEMENTATION\data\train_data.csv')
test_data = pd.read_csv(r'C:\Users\fayaz\Documents\NIDS_IMPLEMENTATION\data\test_data.csv')

# Identify the target column (assuming the last column is the label)
target_column = 'Label' if 'Label' in train_data.columns else train_data.columns[-1]
print(f"Target column: {target_column}")

# Check for NaN values in the loaded data
train_nan_count = train_data.isna().sum().sum()
test_nan_count = test_data.isna().sum().sum()
if train_nan_count > 0 or test_nan_count > 0:
    print(f"WARNING: Found NaN values in data: {train_nan_count} in training, {test_nan_count} in testing")
    print("Filling NaN values with 0...")
    train_data = train_data.fillna(0)
    test_data = test_data.fillna(0)

# Prepare features and target
X_train = train_data.drop(target_column, axis=1)
y_train = train_data[target_column]
X_test = test_data.drop(target_column, axis=1)
y_test = test_data[target_column]

# Final check for NaN values in target variables
if y_train.isna().any():
    print("ERROR: NaN values found in y_train. Dropping those rows...")
    nan_indices = y_train.index[y_train.isna()]
    X_train = X_train.drop(nan_indices)
    y_train = y_train.drop(nan_indices)

if y_test.isna().any():
    print("ERROR: NaN values found in y_test. Dropping those rows...")
    nan_indices = y_test.index[y_test.isna()]
    X_test = X_test.drop(nan_indices)
    y_test = y_test.drop(nan_indices)

print(f"Final training dataset: {X_train.shape} with target shape: {y_train.shape}")
print(f"Final testing dataset: {X_test.shape} with target shape: {y_test.shape}")

# Check class imbalance
print(f"Unique values in target: {y_train.unique()}")
print(f"Target value counts:\n{y_train.value_counts()}")

# Train XGBoost model
print("\n" + "="*50)
print("Training XGBoost model...")
xgb_start_time = time.time()
xgb_model = XGBClassifier(
    n_estimators=100,
    max_depth=8,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    random_state=42,
    n_jobs=-1,
)
xgb_model.fit(X_train, y_train)
xgb_training_time = time.time() - xgb_start_time
print(f"XGBoost model trained in {xgb_training_time:.2f} seconds")

# Save the XGBoost model
joblib.dump(xgb_model, r'C:\Users\fayaz\Documents\NIDS_IMPLEMENTATION\models\xgboost_model.pkl')
print("XGBoost model saved to models directory")

# Evaluate XGBoost model
print("Evaluating XGBoost model...")
start_time = time.time()
y_pred = xgb_model.predict(X_test)
inference_time = time.time() - start_time

# Calculate metrics
accuracy = accuracy_score(y_test, y_pred)
precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average='weighted', zero_division=0)

# Get all possible class labels from both training and test sets
all_classes = np.unique(np.concatenate([y_train.unique(), y_test.unique(), y_pred]))
print(f"All class labels: {all_classes}")

# Generate confusion matrix
cm = confusion_matrix(y_test, y_pred, labels=all_classes)

# Print confusion matrix in a formal way
print("\n" + "="*50)
print("CONFUSION MATRIX:")
print("-"*50)
print(f"Classes: {all_classes}")
print("-"*50)
# Convert to DataFrame for better formatting
cm_df = pd.DataFrame(cm, index=all_classes, columns=all_classes)
cm_df.index.name = 'Actual'
cm_df.columns.name = 'Predicted'
print(cm_df)
print("-"*50)
print("Row values: True labels, Column values: Predicted labels")
print("="*50)

# Create confusion matrix visualization
plt.figure(figsize=(10, 8))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
            xticklabels=all_classes, yticklabels=all_classes)
plt.title('Confusion Matrix - XGBoost')
plt.ylabel('True Label')
plt.xlabel('Predicted Label')
plt.tight_layout()
plt.savefig(r'C:\Users\fayaz\Documents\NIDS_IMPLEMENTATION\results\plots\cm_XGBoost.png')
plt.close()

# Plot feature importances
feature_importances = pd.DataFrame({
    'feature': X_train.columns,
    'importance': xgb_model.feature_importances_
}).sort_values('importance', ascending=False)
    
plt.figure(figsize=(12, 8))
sns.barplot(x='importance', y='feature', data=feature_importances.head(20))
plt.title('Top 20 Feature Importances - XGBoost')
plt.tight_layout()
plt.savefig(r'C:\Users\fayaz\Documents\NIDS_IMPLEMENTATION\results\plots\fi_XGBoost.png')
plt.close()

# Print results
print("\n" + "="*50)
print("XGBoost Model Results:")
print(f"Accuracy: {accuracy*100:.2f}%")
print(f"Precision: {precision*100:.2f}%")
print(f"Recall: {recall*100:.2f}%")
print(f"F1 Score: {f1*100:.2f}%")
print(f"Training Time: {xgb_training_time:.2f} seconds")
print(f"Inference Time: {inference_time:.2f} seconds")
print("\nClassification Report:")
print(classification_report(y_test, y_pred, zero_division=0))

# Save detailed results to text file
with open(r'C:\Users\fayaz\Documents\NIDS_IMPLEMENTATION\results\xgboost_results.txt', 'w') as f:
    f.write(f"Model: XGBoost\n")
    f.write(f"Training time: {xgb_training_time:.2f} seconds\n")
    f.write(f"Inference time: {inference_time:.2f} seconds\n")
    f.write(f"Accuracy: {accuracy*100:.2f}%\n")
    f.write(f"Precision: {precision*100:.2f}%\n")
    f.write(f"Recall: {recall*100:.2f}%\n")
    f.write(f"F1 Score: {f1*100:.2f}%\n")
    f.write("\nConfusion Matrix:\n")
    f.write(f"{cm_df.to_string()}\n\n")
    f.write("\nClassification Report:\n")
    f.write(classification_report(y_test, y_pred, zero_division=0))

print("\nEvaluation complete!")
print("Results and visualizations saved to results directory")