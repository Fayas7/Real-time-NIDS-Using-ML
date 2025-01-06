import pandas as pd

# Load the large dataset
large_data = pd.read_csv(r'C:\Users\fayaz\Documents\project final year\dataset\archive\Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv')  # Using raw string
# Sample a small amount of data (e.g., 10% of the dataset)
sampled_data = large_data.sample(frac=0.1, random_state=42)  # 10% of the data

sampled_data.to_csv(r'C:\Users\fayaz\Documents\NIDS_IMPLEMENTATION\data\train_data.csv', index=False)  # Using raw string
train_data = large_data.sample(frac=0.9, random_state=43)  # 10% of the data with a different random state
train_data.to_csv(r'C:\Users\fayaz\Documents\NIDS_IMPLEMENTATION\data\train_data.csv', index=False)  # Save test data
print("Sampled test data saved to 'C:/Users/fayaz/Documents/NIDS_IMPLEMENTATION/data/test_data.csv'.")

# Remove the sampled training data from the original dataset for removing overlap
remaining_data = large_data.drop(train_data.index)
test_data = remaining_data.sample(frac=0.1, random_state=43)  # 10% of the remaining data
test_data.to_csv(r'C:\Users\fayaz\Documents\NIDS_IMPLEMENTATION\data\test_data.csv', index=False)  # Save test data
print("Sampled test data saved to 'C:/Users/fayaz/Documents/NIDS_IMPLEMENTATION/data/test_data.csv'.")

