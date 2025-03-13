import pandas as pd
import numpy as np
import time
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_recall_fscore_support
from xgboost import XGBClassifier
import os
from sklearn.preprocessing import LabelEncoder

# Create directory for saving plots
os.makedirs(r'C:\Users\fayaz\Documents\NIDS_IMPLEMENTATION\results\plots', exist_ok=True)

# Load the combined preprocessed data
print("Loading combined preprocessed data...")
train_data = pd.read_csv(r'C:\Users\fayaz\Documents\NIDS_IMPLEMENTATION\data\combined_train_data.csv')
test_data = pd.read_csv(r'C:\Users\fayaz\Documents\NIDS_IMPLEMENTATION\data\combined_test_data.csv')

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
print(f"Unique values in training target: {y_train.unique()}")
print(f"Training target value counts:\n{y_train.value_counts()}")
print(f"Unique values in testing target: {y_test.unique()}")
print(f"Testing target value counts:\n{y_test.value_counts()}")

# Use LabelEncoder to transform non-consecutive labels to consecutive integers
print("Encoding class labels to consecutive integers...")
le = LabelEncoder()
le.fit(np.unique(np.concatenate([y_train.unique(), y_test.unique()])))  # Fit on all possible labels
y_train_encoded = le.transform(y_train)
y_test_encoded = le.transform(y_test)

# Show the mapping from original labels to encoded labels
mapping = {float(original): encoded for original, encoded in zip(le.classes_, range(len(le.classes_)))}
print(f"Label mapping: {mapping}")

# Calculate class weights to handle imbalance (using encoded labels)
class_counts = pd.Series(y_train_encoded).value_counts()
total_samples = len(y_train_encoded)
class_weights = {class_label: total_samples / (len(class_counts) * count) 
                for class_label, count in class_counts.items()}
print(f"Class weights for balancing (encoded labels): {class_weights}")

# Train XGBoost model with adjusted parameters for larger dataset
print("\n" + "="*50)
print("Training XGBoost model on combined data...")
xgb_start_time = time.time()
xgb_model = XGBClassifier(
    n_estimators=150,        # Increased from 100 to handle more complex data
    max_depth=10,            # Increased from 8 to capture more complex patterns
    learning_rate=0.05,      # Reduced to prevent overfitting with larger dataset
    subsample=0.7,           # Adjusted for better generalization
    colsample_bytree=0.7,    # Adjusted for better generalization
    random_state=42,
    n_jobs=-1,               # Use all available cores
    reg_alpha=0.1,           # L1 regularization to reduce overfitting
    reg_lambda=1.0,          # L2 regularization to reduce overfitting
)
xgb_model.fit(X_train, y_train_encoded)  # Use encoded labels
xgb_training_time = time.time() - xgb_start_time
print(f"XGBoost model trained in {xgb_training_time:.2f} seconds")

# Save the XGBoost model
model_save_path = r'C:\Users\fayaz\Documents\NIDS_IMPLEMENTATION\models\xgboost_combined_model.pkl'
joblib.dump({'model': xgb_model, 'label_encoder': le}, model_save_path)
print(f"XGBoost model saved to: {model_save_path}")

# Evaluate XGBoost model
print("Evaluating XGBoost model...")
start_time = time.time()
y_pred_encoded = xgb_model.predict(X_test)
inference_time = time.time() - start_time
print(f"Inference completed in {inference_time:.2f} seconds")

# Convert predictions back to original labels for interpretation
y_pred_original = le.inverse_transform(y_pred_encoded)

# Calculate metrics using encoded values (this is fine since the mapping is 1:1)
accuracy = accuracy_score(y_test_encoded, y_pred_encoded)
precision, recall, f1, _ = precision_recall_fscore_support(y_test_encoded, y_pred_encoded, average='weighted', zero_division=0)

# Determine actual classes present in test set
present_classes_encoded = np.unique(y_test_encoded)
present_classes_original = le.inverse_transform(present_classes_encoded)

print(f"Classes present in test data (encoded): {present_classes_encoded}")
print(f"Classes present in test data (original): {present_classes_original}")

# Generate confusion matrix using encoded values for present classes only
cm = confusion_matrix(y_test_encoded, y_pred_encoded, labels=present_classes_encoded)

# Print confusion matrix with original class labels for better interpretation
print("\n" + "="*50)
print("CONFUSION MATRIX:")
print("-"*50)
print(f"Classes present in test data (original): {present_classes_original}")
print("-"*50)
# Convert to DataFrame for better formatting - using original labels for display
cm_df = pd.DataFrame(cm, 
                     index=present_classes_original,
                     columns=present_classes_original)
cm_df.index.name = 'Actual'
cm_df.columns.name = 'Predicted'
print(cm_df)
print("-"*50)
print("Row values: True labels, Column values: Predicted labels")
print("="*50)

# Create confusion matrix visualization with original labels
plt.figure(figsize=(12, 10))  # Larger size for potentially more classes
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
            xticklabels=present_classes_original, yticklabels=present_classes_original)
plt.title('Confusion Matrix - XGBoost (Combined Data)')
plt.ylabel('True Label')
plt.xlabel('Predicted Label')
plt.tight_layout()
plt.savefig(r'C:\Users\fayaz\Documents\NIDS_IMPLEMENTATION\results\plots\cm_XGBoost_combined.png')
plt.close()

# Plot feature importances
feature_importances = pd.DataFrame({
    'feature': X_train.columns,
    'importance': xgb_model.feature_importances_
}).sort_values('importance', ascending=False)
    
plt.figure(figsize=(14, 10))  # Larger figure for better readability
sns.barplot(x='importance', y='feature', data=feature_importances.head(20))
plt.title('Top 20 Feature Importances - XGBoost (Combined Data)')
plt.tight_layout()
plt.savefig(r'C:\Users\fayaz\Documents\NIDS_IMPLEMENTATION\results\plots\fi_XGBoost_combined.png')
plt.close()

# Per-class performance analysis - only use classes present in test data
target_names = [str(float(le.inverse_transform([i])[0])) for i in present_classes_encoded]
print(f"Using target names for classification report: {target_names}")

class_report = classification_report(y_test_encoded, y_pred_encoded, 
                                    labels=present_classes_encoded,
                                    target_names=target_names,
                                    output_dict=True, zero_division=0)
class_metrics = pd.DataFrame(class_report).transpose()
class_metrics = class_metrics.drop(['accuracy', 'macro avg', 'weighted avg'], errors='ignore')
class_metrics = class_metrics.sort_values('support', ascending=False)

# Plot per-class metrics
plt.figure(figsize=(15, 8))
class_metrics[['precision', 'recall', 'f1-score']].plot(kind='bar')
plt.title('Per-Class Performance Metrics')
plt.grid(axis='y', linestyle='--', alpha=0.7)
plt.tight_layout()
plt.savefig(r'C:\Users\fayaz\Documents\NIDS_IMPLEMENTATION\results\plots\per_class_metrics_combined.png')
plt.close()

# Print results
print("\n" + "="*50)
print("XGBoost Model Results (Combined Dataset):")
print(f"Accuracy: {accuracy*100:.2f}%")
print(f"Precision: {precision*100:.2f}%")
print(f"Recall: {recall*100:.2f}%")
print(f"F1 Score: {f1*100:.2f}%")
print(f"Training Time: {xgb_training_time:.2f} seconds")
print(f"Inference Time: {inference_time:.2f} seconds")
print("\nClassification Report:")
print(classification_report(y_test_encoded, y_pred_encoded, 
                          labels=present_classes_encoded, 
                          target_names=target_names, 
                          zero_division=0))

# Save detailed results to text file
with open(r'C:\Users\fayaz\Documents\NIDS_IMPLEMENTATION\results\xgboost_combined_results.txt', 'w') as f:
    f.write(f"Model: XGBoost (Trained on Combined Dataset)\n")
    f.write(f"Dataset: Thursday + Monday + Wednesday\n")
    f.write(f"Training samples: {len(X_train)}\n")
    f.write(f"Testing samples: {len(X_test)}\n\n")
    f.write(f"Label mapping: {mapping}\n\n")
    f.write(f"Training time: {xgb_training_time:.2f} seconds\n")
    f.write(f"Inference time: {inference_time:.2f} seconds\n")
    f.write(f"Accuracy: {accuracy*100:.2f}%\n")
    f.write(f"Precision: {precision*100:.2f}%\n")
    f.write(f"Recall: {recall*100:.2f}%\n")
    f.write(f"F1 Score: {f1*100:.2f}%\n")
    f.write("\nConfusion Matrix:\n")
    f.write(f"{cm_df.to_string()}\n\n")
    f.write("\nClassification Report:\n")
    f.write(classification_report(y_test_encoded, y_pred_encoded, 
                                labels=present_classes_encoded, 
                                target_names=target_names, 
                                zero_division=0))
    f.write("\nTop 20 Feature Importances:\n")
    f.write(f"{feature_importances.head(20).to_string()}\n")

print("\nEvaluation complete!")
print("Results and visualizations saved to results directory")