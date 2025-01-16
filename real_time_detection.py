'''import logging
import pandas as pd
import joblib  # Import joblib directly
import subprocess
import sys
sys.stdout.reconfigure(line_buffering=True)

# Set up logging,it is used foer logging messasges,here it is information about anomalies or normal traffic
logging.basicConfig(level=logging.INFO, filename='intrusion_logs.txt', filemode='w', format='%(asctime)s - %(message)s')
 #The INFO level is used to log informational messages that highlight the progress of the application
                                        #at a high level. These messages are typically used to confirm that things are working as expected.
# Load the trained model and label encoder from the current directory
model = joblib.load('model.joblib')  
label_encoder = joblib.load('label_encoder.joblib')  # 

def capture_and_extract_features():
    # Use tshark to capture packets and extract relevant features
    command = [
        r"C:\Program Files\Wireshark\tshark.exe",  # Correctly formatted raw string
        '-i', '18',  # wifi wireless command:tshark -i 1ECED4D8-EA64-4185-9D8E-88552A89EEAE
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
    detect_intrusions()'''

import logging
import pandas as pd
import joblib
import subprocess
import sys
from datetime import datetime

sys.stdout.reconfigure(line_buffering=True)

# Set up logging to capture logs in a file
logging.basicConfig(level=logging.INFO, filename='intrusion_logs.txt', filemode='w', format='%(asctime)s - %(message)s')

# Load the trained model and label encoder
model = joblib.load('model.joblib')
label_encoder = joblib.load('label_encoder.joblib')

# Define the time window for logging
START_TIME = datetime(2025, 1, 14, 14, 0, 0)  # Start logging at 14:00
END_TIME = datetime(2025, 1, 14, 16, 0, 0)    # Stop logging at 16:00

def is_within_time_window():
    """Check if the current time is within the defined time window."""
    current_time = datetime.now()
    return START_TIME <= current_time <= END_TIME

def capture_and_extract_features():
    """Use tshark to capture packets and extract relevant features."""
    command = [
        r"C:\\Program Files\\Wireshark\\tshark.exe",  # Path to tshark
        '-i', '18',  # Replace '18' with your network interface ID
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

    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Read output line by line
        while True:
            output = process.stdout.readline()
            if output == b"" and process.poll() is not None:
                break
            if output:
                features = output.decode('utf-8').strip().split('\t')
                if len(features) >= 6:  # Ensure enough features
                    yield features
    except Exception as e:
        logging.error("Error during packet capture: %s", e)

def preprocess_features(features):
    """Convert features to a DataFrame and preprocess as needed."""
    df = pd.DataFrame([features], columns=[
        'ip.src', 'ip.dst', 'tcp.srcport', 'tcp.dstport', 'udp.srcport', 'udp.dstport', 'frame.len', 'frame.time_epoch'
    ])

    # Convert numerical features to appropriate types
    df['frame.len'] = pd.to_numeric(df['frame.len'], errors='coerce')
    return df

def detect_intrusions():
    """Detect intrusions in real-time."""
    for features in capture_and_extract_features():
        if not is_within_time_window():
            logging.info("Time window ended. Stopping detection.")
            break

        # Preprocess the features
        processed_features = preprocess_features(features)

        # Predict using the model
        try:
            prediction = model.predict(processed_features)

            # Log the prediction
            if prediction == 'anomaly':
                logging.info("Intrusion detected! Features: %s", processed_features.to_dict(orient='records'))
            else:
                logging.info("Normal traffic detected. Features: %s", processed_features.to_dict(orient='records'))
        except Exception as e:
            logging.error("Error during prediction: %s", e)

if __name__ == "__main__":
    logging.info("Starting real-time intrusion detection...")
    detect_intrusions()

