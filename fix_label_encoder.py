import joblib
import numpy as np
from sklearn.preprocessing import LabelEncoder

# Load the existing label encoder
encoder_path = 'label_encoder.joblib'  # Make sure this is the correct path
label_encoder = joblib.load(encoder_path)

# Print existing classes
print("Existing classes:", label_encoder.classes_)

# Ensure "Bot" is included in the label classes
new_classes = np.append(label_encoder.classes_, "Bot") if "Bot" not in label_encoder.classes_ else label_encoder.classes_

# Create a new LabelEncoder and fit with updated classes
new_label_encoder = LabelEncoder()
new_label_encoder.fit(new_classes)

# Save the updated encoder
joblib.dump(new_label_encoder, encoder_path)

print("Updated label encoder saved successfully with 'Bot' included!")
