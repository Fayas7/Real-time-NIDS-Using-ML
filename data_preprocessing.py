import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
import os
import joblib

# Create required directories if they don't exist
os.makedirs(r'C:\Users\fayaz\Documents\NIDS_IMPLEMENTATION\models', exist_ok=True)
os.makedirs(r'C:\Users\fayaz\Documents\NIDS_IMPLEMENTATION\results', exist_ok=True)
os.makedirs(r'C:\Users\fayaz\Documents\NIDS_IMPLEMENTATION\data', exist_ok=True)

# Define all dataset paths
file_paths = {
    'Thursday': r'C:\Users\fayaz\Documents\project final year\dataset\archive\Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv',
    'Monday': r'C:\Users\fayaz\Documents\project final year\dataset\archive\Monday-WorkingHours.pcap_ISCX.csv',
    'Wednesday': r'C:\Users\fayaz\Documents\project final year\dataset\archive\Wednesday-workingHours.pcap_ISCX.csv'
}

# Load all datasets
datasets = {}
for day, path in file_paths.items():
    print(f"Loading data from {path}...")
    try:
        datasets[day] = pd.read_csv(path)
        print(f"{day} dataset shape: {datasets[day].shape}")
    except Exception as e:
        print(f"Error loading {day} data: {e}")
        exit(1)

# Find common columns across all datasets
common_columns = set(datasets['Thursday'].columns)
for day, data in datasets.items():
    common_columns = common_columns.intersection(set(data.columns))

if len(common_columns) < len(datasets['Thursday'].columns):
    print(f"Warning: The datasets have different columns. Using only the {len(common_columns)} common columns.")
    # Keep only common columns in all datasets
    for day in datasets:
        datasets[day] = datasets[day][list(common_columns)]

# Combine all datasets
print("Combining datasets...")
data = pd.concat(list(datasets.values()), ignore_index=True)
print(f"Combined dataset shape: {data.shape}")

# Identify the target column (assuming the last column is the label)
target_column = 'Label' if 'Label' in data.columns else data.columns[-1]
print(f"Using '{target_column}' as the target column")

# Check for NaN values in the target column
nan_count_target = data[target_column].isna().sum()
if nan_count_target > 0:
    print(f"WARNING: Found {nan_count_target} NaN values in target column '{target_column}'")
    print("Removing rows with NaN target values")
    data = data.dropna(subset=[target_column])
    print(f"Dataset shape after removing NaN targets: {data.shape}")

# Handle missing values in feature columns
print("Handling missing values in features...")
data = data.replace([np.inf, -np.inf], np.nan)
nan_counts = data.isna().sum()
print(f"Columns with NaN values: {nan_counts[nan_counts > 0].to_dict()}")

# Use mean for numerical columns with NaNs
numerical_cols = data.select_dtypes(include=['int64', 'float64']).columns.tolist()
for col in numerical_cols:
    if data[col].isna().sum() > 0:
        data[col] = data[col].fillna(data[col].mean())

# Identify categorical columns
categorical_cols = data.select_dtypes(include=['object']).columns.tolist()
print(f"Categorical columns: {categorical_cols}")

# Handle categorical columns
print("Encoding categorical features...")
label_encoders = {}
for col in categorical_cols:
    # Fill NaN values with 'Unknown' before encoding
    if data[col].isna().sum() > 0:
        data[col] = data[col].fillna('Unknown')
    
    label_encoders[col] = LabelEncoder()
    data[col] = label_encoders[col].fit_transform(data[col].astype(str))

# Prepare features and target
X = data.drop(target_column, axis=1)
y = data[target_column]

# Perform a final check for NaN values
if X.isna().any().any():
    print("WARNING: There are still NaN values in the features. Filling remaining with 0.")
    X = X.fillna(0)

if y.isna().any():
    print("ERROR: There are still NaN values in the target column after preprocessing.")
    print("This should not happen as we dropped those rows earlier.")
    exit(1)

# Split the data into training (80%) and testing (20%) sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y if len(np.unique(y)) < 50 else None)

print(f"Training dataset size: {X_train.shape[0]} samples ({X_train.shape[0]/data.shape[0]*100:.1f}% of combined data)")
print(f"Testing dataset size: {X_test.shape[0]} samples ({X_test.shape[0]/data.shape[0]*100:.1f}% of combined data)")

# Feature scaling
print("Scaling features...")
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Final verification for NaN values (after scaling)
if np.isnan(X_train_scaled).any() or np.isnan(X_test_scaled).any():
    print("WARNING: NaN values detected after scaling. Replacing with zeros.")
    X_train_scaled = np.nan_to_num(X_train_scaled)
    X_test_scaled = np.nan_to_num(X_test_scaled)

# Save preprocessed data
train_data = pd.DataFrame(X_train_scaled, columns=X.columns)
train_data[target_column] = y_train
test_data = pd.DataFrame(X_test_scaled, columns=X.columns)
test_data[target_column] = y_test

# Final check for NaN values in assembled DataFrames
if train_data.isna().any().any() or test_data.isna().any().any():
    print("WARNING: NaN values still present in final data. Fixing...")
    train_data = train_data.fillna(0)
    test_data = test_data.fillna(0)

# Per-dataset statistics
print("\nSamples from each dataset:")
for day, dataset in datasets.items():
    print(f"  {day}: {len(dataset)} samples ({len(dataset)/len(data)*100:.2f}% of combined data)")

# Create a summary of attack types and their counts
print("\nDistribution of attack types in the combined dataset:")
attack_distribution = data[target_column].value_counts()
for attack, count in attack_distribution.items():
    print(f"  {attack}: {count} samples ({count/len(data)*100:.2f}%)")

# Generate per-day attack type distribution
print("\nAttack distribution by day:")
for day, dataset in datasets.items():
    print(f"\n{day} attack distribution:")
    day_distribution = dataset[target_column].value_counts()
    for attack, count in day_distribution.items():
        print(f"  {attack}: {count} samples ({count/len(dataset)*100:.2f}% of {day} data)")

train_output_path = r'C:\Users\fayaz\Documents\NIDS_IMPLEMENTATION\data\combined_train_data.csv'
test_output_path = r'C:\Users\fayaz\Documents\NIDS_IMPLEMENTATION\data\combined_test_data.csv'

train_data.to_csv(train_output_path, index=False)
test_data.to_csv(test_output_path, index=False)

# Save the column names, scaler, and label encoders for future use
joblib.dump(scaler, r'C:\Users\fayaz\Documents\NIDS_IMPLEMENTATION\models\combined_scaler.pkl')
joblib.dump(label_encoders, r'C:\Users\fayaz\Documents\NIDS_IMPLEMENTATION\models\combined_label_encoders.pkl')
joblib.dump(X.columns.tolist(), r'C:\Users\fayaz\Documents\NIDS_IMPLEMENTATION\models\combined_feature_columns.pkl')

print(f"Preprocessing complete!")
print(f"Combined training data saved to: {train_output_path}")
print(f"Combined testing data saved to: {test_output_path}")
print(f"Preprocessing artifacts saved to models directory")