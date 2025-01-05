import pandas as pd
from sklearn.preprocessing import StandardScaler

# Load the training and test datasets
train_data = pd.read_csv(r'C:\Users\fayaz\Documents\NIDS_IMPLEMENTATION\data\train_data.csv')
test_data = pd.read_csv(r'C:\Users\fayaz\Documents\NIDS_IMPLEMENTATION\data\test_data.csv')

# Check for missing values
print("Missing values in training data:\n", train_data.isnull().sum())
print("Missing values in test data:\n", test_data.isnull().sum())

# Check column names
print("Columns in training data:", train_data.columns.tolist())
print("Columns in test data:", test_data.columns.tolist())

# Strip whitespace from column names
train_data.columns = train_data.columns.str.strip()
test_data.columns = test_data.columns.str.strip()

# Update 'Label' to the actual target column name if necessary
target_column = 'Label'  # Change this if the actual column name is different

if target_column not in train_data.columns:
    raise KeyError(f"Target column '{target_column}' not found in training data.")

# Prepare feature and target datasets
X_train = train_data.drop(target_column, axis=1)
y_train = train_data[target_column]
X_test = test_data.drop(target_column, axis=1)
y_test = test_data[target_column]

# Convert to numeric to avoid FutureWarning
X_train = X_train.apply(pd.to_numeric, errors='coerce')
X_test = X_test.apply(pd.to_numeric, errors='coerce')

# Handle missing values (fill with mean for numeric columns)
numeric_cols = X_train.select_dtypes(include=['float64', 'int64']).columns
X_train[numeric_cols] = X_train[numeric_cols].fillna(X_train[numeric_cols].mean())
X_test[numeric_cols] = X_test[numeric_cols].fillna(X_test[numeric_cols].mean())

# Check for infinite values
print("Infinite values in training data:\n", X_train.isin([float('inf'), float('-inf')]).sum())
print("Infinite values in test data:\n", X_test.isin([float('inf'), float('-inf')]).sum())

# Replace infinite values with NaN and fill NaN values
X_train.replace([float('inf'), float('-inf')], pd.NA, inplace=True)
X_train.fillna(X_train.mean(), inplace=True)  # Fill NaN values with the mean

X_test.replace([float('inf'), float('-inf')], pd.NA, inplace=True)
X_test.fillna(X_test.mean(), inplace=True)  # Fill NaN values with the mean

# Scale the features
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Finalize the training and test datasets
X_train_final = pd.DataFrame(X_train_scaled, columns=X_train.columns)
y_train_final = y_train.reset_index(drop=True)  # Reset index for consistency
X_test_final = pd.DataFrame(X_test_scaled, columns=X_test.columns)
y_test_final = y_test.reset_index(drop=True)  # Reset index for consistency

# Save the processed data
X_train_final.to_csv(r'C:\Users\fayaz\Documents\NIDS_IMPLEMENTATION\data\X_train_processed.csv', index=False)
y_train_final.to_csv(r'C:\Users\fayaz\Documents\NIDS_IMPLEMENTATION\data\y_train_processed.csv', index=False)
X_test_final.to_csv(r'C:\Users\fayaz\Documents\NIDS_IMPLEMENTATION\data\X_test_processed.csv', index=False)
y_test_final.to_csv(r'C:\Users\fayaz\Documents\NIDS_IMPLEMENTATION\data\y_test_processed.csv', index=False)

print("Data preprocessing completed and processed data saved.")