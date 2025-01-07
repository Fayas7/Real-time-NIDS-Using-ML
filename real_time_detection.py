import logging
import pandas as pd
import joblib  # Import joblib directly
import subprocess

# Set up logging
logging.basicConfig(level=logging.INFO)

# Load the trained model and label encoder from the current directory
model = joblib.load('model.joblib')  # Adjusted path
label_encoder = joblib.load('label_encoder.joblib')  # Adjusted path

def capture_and_extract_features():
    # Use tshark to capture packets and extract relevant features
    command = [
        r"C:\Program Files\Wireshark\tshark.exe",  # Correctly formatted raw string
        '-i', '19',  # Replace '19' with your network interface ID
        '-T', 'fields',
        '-e', 'ip.src',
        '-e', 'ip.dst',
        '-e', 'tcp.srcport',
        '-e', 'tcp.dstport',
        '-e', 'udp.srcport',
        '-e', 'udp.dstport',
        '-e', 'frame.len',
        '-e', 'frame.time_epoch'
    ]

    # Run the command and capture output
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Read output line by line
    while True:
        output = process.stdout.readline()
        if output == b"" and process.poll() is not None:
            break
        if output:
            # Decode the output and split into features
            features = output.decode('utf-8').strip().split('\t')
            if len(features) >= 6:  # Ensure we have enough features
                yield features

def preprocess_features(features):
    # Convert features to a DataFrame and preprocess as needed
    df = pd.DataFrame([features], columns=[
        'ip.src', 'ip.dst', 'tcp.srcport', 'tcp.dstport', 'udp.srcport', 'udp.dstport', 'frame.len', 'frame.time_epoch'
    ])

    # Convert numerical features to appropriate types
    df['frame.len'] = pd.to_numeric(df['frame.len'], errors='coerce')
    # Add more preprocessing steps as needed (e.g., normalization, encoding)

    return df

def detect_intrusions():
    for features in capture_and_extract_features():
        # Preprocess the features
        processed_features = preprocess_features(features)

        # Predict using the model
        prediction = model.predict(processed_features)

        # Log the prediction
        if prediction == 'anomaly':
            logging.info("Intrusion detected! Features: %s", processed_features.to_dict(orient='records'))
        else:
            logging.info("Normal traffic detected. Features: %s", processed_features.to_dict(orient='records'))

if __name__ == "__main__":
    detect_intrusions()
