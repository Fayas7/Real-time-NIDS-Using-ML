'''
import logging
from fastapi import FastAPI, BackgroundTasks, WebSocket
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import pandas as pd
import joblib
from datetime import datetime, timedelta
import asyncio
import os
import json
from pydantic import BaseModel
from scapy.all import sniff, IP, TCP, UDP
import threading
from queue import Queue
from typing import Dict, List, Optional

# Add WebSocket connections store
active_connections = []
packet_queue = Queue()

class IntrusionAnalysis:
    def __init__(self, packet_data: Dict):
        self.packet_data = packet_data
        self.evidence: List[str] = []
        self.intrusion_type = "Unknown"
        self.is_anomaly = False
        self.analyze()

    def check_packet_size(self):
        """Check for abnormally large packets"""
        if self.packet_data["frame.len"] > 1500:
            self.evidence.append(f"Abnormally large packet size: {self.packet_data['frame.len']} bytes")
            self.intrusion_type = "Potential DDoS Attack"
            self.is_anomaly = True

    def check_port_scanning(self):
        """Check for port scanning behavior"""
        if self.packet_data["tcp.dstport"] == 0 and self.packet_data["udp.dstport"] == 0:
            self.evidence.append("Port scanning behavior detected")
            self.intrusion_type = "Port Scanning"
            self.is_anomaly = True

    def check_suspicious_ports(self):
        """Check for suspicious port numbers"""
        suspicious_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            445: "SMB",
            3389: "RDP"
        }
        
        dst_port = self.packet_data["tcp.dstport"]
        if dst_port in suspicious_ports:
            self.evidence.append(
                f"Suspicious {suspicious_ports[dst_port]} port ({dst_port}) access attempt"
            )
            self.intrusion_type = f"Service Attack Attempt ({suspicious_ports[dst_port]})"
            self.is_anomaly = True

    def analyze(self):
        """Run all analysis checks"""
        try:
            self.check_packet_size()
            self.check_port_scanning()
            self.check_suspicious_ports()
        except Exception as e:
            logging.error(f"Error during intrusion analysis: {str(e)}")
            self.evidence.append(f"Analysis error: {str(e)}")
            self.is_anomaly = True
            self.intrusion_type = "Analysis Error"

    def to_dict(self):
        """Convert analysis results to dictionary"""
        return {
            "is_anomaly": self.is_anomaly,
            "type": self.intrusion_type,
            "evidence": self.evidence
        }

@asynccontextmanager
async def lifespan(app: FastAPI):
    logging.info("Starting real-time intrusion detection...")
    yield
    logging.info("Shutting down intrusion detection system...")

app = FastAPI(lifespan=lifespan)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Set up logging with more detailed format
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

# Mock data for testing when model is not available
MOCK_MODE = True

if not MOCK_MODE:
    try:
        MODEL_PATH = os.getenv('MODEL_PATH', 'model.joblib')
        LABEL_ENCODER_PATH = os.getenv('LABEL_ENCODER_PATH', 'label_encoder.joblib')
        model = joblib.load(MODEL_PATH)
        label_encoder = joblib.load(LABEL_ENCODER_PATH)
    except FileNotFoundError as e:
        logging.warning("Model files not found, running in mock mode")
        MOCK_MODE = True

def packet_callback(packet):
    """Process captured packets and put them in the queue"""
    try:
        if IP in packet:
            packet_data = {
                "ip.src": packet[IP].src,
                "ip.dst": packet[IP].dst,
                "tcp.srcport": packet[TCP].sport if TCP in packet else 0,
                "tcp.dstport": packet[TCP].dport if TCP in packet else 0,
                "udp.srcport": packet[UDP].sport if UDP in packet else 0,
                "udp.dstport": packet[UDP].dport if UDP in packet else 0,
                "frame.len": len(packet),
                "frame.time_epoch": datetime.now().timestamp()
            }
            packet_queue.put(packet_data)
    except Exception as e:
        logging.error(f"Error in packet callback: {str(e)}")
        # Put error packet in queue to maintain monitoring
        error_packet = {
            "ip.src": "error",
            "ip.dst": "error",
            "tcp.srcport": 0,
            "tcp.dstport": 0,
            "udp.srcport": 0,
            "udp.dstport": 0,
            "frame.len": 0,
            "frame.time_epoch": datetime.now().timestamp(),
            "error": str(e)
        }
        packet_queue.put(error_packet)

def start_packet_capture():
    """Start packet capture in a separate thread"""
    try:
        sniff(prn=packet_callback, store=0)
    except Exception as e:
        logging.error(f"Packet capture error: {str(e)}")

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    logging.info("New WebSocket connection established")
    
    # Start packet capture in a separate thread if not already running
    if not hasattr(app.state, "capture_thread") or not app.state.capture_thread.is_alive():
        app.state.capture_thread = threading.Thread(target=start_packet_capture, daemon=True)
        app.state.capture_thread.start()
    
    try:
        while True:
            try:
                # Process packets from the queue
                if not packet_queue.empty():
                    packet_data = packet_queue.get_nowait()
                    
                    # Check if this is an error packet
                    if "error" in packet_data:
                        message = {
                            "features": packet_data,
                            "prediction_label": "error",
                            "intrusion_type": "System Error",
                            "evidence": [f"System error occurred: {packet_data['error']}"],
                            "timestamp": datetime.now().isoformat()
                        }
                    else:
                        # Analyze packet for intrusion
                        analysis = IntrusionAnalysis(packet_data)
                        analysis_result = analysis.to_dict()
                        
                        message = {
                            "features": packet_data,
                            "prediction_label": "anomaly" if analysis_result["is_anomaly"] else "normal",
                            "intrusion_type": analysis_result["type"],
                            "evidence": analysis_result["evidence"],
                            "timestamp": datetime.now().isoformat()
                        }
                    
                    await websocket.send_text(json.dumps(message))
                    
                    if message["prediction_label"] in ["anomaly", "error"]:
                        logging.warning(
                            f"Alert: {message['intrusion_type']}\n"
                            f"Evidence: {', '.join(message['evidence'])}"
                        )
                    else:
                        logging.info(f"Normal packet: {packet_data['ip.src']} -> {packet_data['ip.dst']}")
                
                await asyncio.sleep(0.1)  # Small delay to prevent CPU overload
                
            except Exception as e:
                logging.error(f"Error processing packet: {str(e)}")
                # Send error message to client
                error_message = {
                    "features": {},
                    "prediction_label": "error",
                    "intrusion_type": "Processing Error",
                    "evidence": [f"Error processing packet: {str(e)}"],
                    "timestamp": datetime.now().isoformat()
                }
                try:
                    await websocket.send_text(json.dumps(error_message))
                except Exception as ws_error:
                    logging.error(f"Failed to send error message: {str(ws_error)}")
                continue
                
    except Exception as e:
        logging.error(f"WebSocket error: {str(e)}")
    finally:
        if websocket in active_connections:
            active_connections.remove(websocket)
        logging.info("WebSocket connection closed")

# Mount static files AFTER all routes are defined
app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")

if __name__ == "__main__":
    import uvicorn
    logging.info("Starting NIDS application...")
    uvicorn.run(app, host="127.0.0.1", port=8000)'
'''
import pandas as pd
import numpy as np
import joblib
import os
import time
from datetime import datetime

def load_models_and_preprocessing():
    """Load all required models and preprocessing components"""
    models_dir = r'C:\Users\fayaz\Documents\NIDS_IMPLEMENTATION\models'
    
    # Load preprocessing components
    scaler = joblib.load(os.path.join(models_dir, 'scaler.pkl'))
    feature_columns = joblib.load(os.path.join(models_dir, 'feature_columns.pkl'))
    
    try:
        label_encoders = joblib.load(os.path.join(models_dir, 'label_encoders.pkl'))
    except:
        label_encoders = {}
    
    # Load models
    rf_model = joblib.load(os.path.join(models_dir, 'random_forest_model.pkl'))
    xgb_model = joblib.load(os.path.join(models_dir, 'xgboost_model.pkl'))
    
    return {
        'scaler': scaler,
        'feature_columns': feature_columns,
        'label_encoders': label_encoders,
        'rf_model': rf_model,
        'xgb_model': xgb_model
    }

def preprocess_network_data(data, components):
    """Preprocess network data for prediction"""
    # Ensure all required columns are present
    for col in components['feature_columns']:
        if col not in data.columns:
            data[col] = 0  # Default value for missing columns
    
    # Select only the columns used during training
    data = data[components['feature_columns']]
    
    # Handle categorical columns
    for col, encoder in components['label_encoders'].items():
        if col in data.columns:
            data[col] = data[col].astype(str)
            try:
                data[col] = encoder.transform(data[col])
            except:
                # Handle unseen categories by setting them to a default value
                data[col] = 0
    
    # Handle missing values
    data = data.replace([np.inf, -np.inf], np.nan)
    data = data.fillna(0)  # Use 0 for missing values in production
    
    # Scale the data
    data_scaled = components['scaler'].transform(data)
    
    return data_scaled

def predict_intrusion(data_scaled, components, ensemble=True):
    """Make predictions using one or both models"""
    start_time = time.time()
    
    if ensemble:
        # Voting ensemble (majority vote)
        rf_pred = components['rf_model'].predict(data_scaled)
        xgb_pred = components['xgb_model'].predict(data_scaled)
        
        # Get probabilities for confidence
        rf_prob = components['rf_model'].predict_proba(data_scaled)
        xgb_prob = components['xgb_model'].predict_proba(data_scaled)
        
        # Average the probabilities for ensemble confidence
        ensemble_prob = (rf_prob + xgb_prob) / 2
        
        # Get the class with highest average probability
        final_pred = np.argmax(ensemble_prob, axis=1)
        confidence = np.max(ensemble_prob, axis=1)
    else:
        # Just use XGBoost (often faster and similarly accurate)
        final_pred = components['xgb_model'].predict(data_scaled)
        prob = components['xgb_model'].predict_proba(data_scaled)
        confidence = np.max(prob, axis=1)
    
    inference_time = time.time() - start_time
    
    return final_pred, confidence, inference_time

def log_detection(pred, confidence, inference_time, data):
    """Log detection results"""
    log_dir = r'C:\Users\fayaz\Documents\NIDS_IMPLEMENTATION\logs'
    os.makedirs(log_dir, exist_ok=True)
    
    log_file = os.path.join(log_dir, f'detections_{datetime.now().strftime("%Y%m%d")}.csv')
    file_exists = os.path.isfile(log_file)
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Create log entry
    log_data = pd.DataFrame({
        'timestamp': [timestamp],
        'prediction': [pred[0]],
        'confidence': [confidence[0]],
        'inference_time_ms': [inference_time * 1000]
    })
    
    # Add any relevant original data fields
    if 'src_ip' in data.columns:
        log_data['src_ip'] = data['src_ip'].iloc[0]
    if 'dst_ip' in data.columns:
        log_data['dst_ip'] = data['dst_ip'].iloc[0]
    
    # Append to log file
    log_data.to_csv(log_file, mode='a', header=not file_exists, index=False)

def simulate_live_detection():
    """Simulate live detection on test data"""
    print("Loading models and preprocessing components...")
    components = load_models_and_preprocessing()
    
    print("Loading test data for simulation...")
    test_data = pd.read_csv(r'C:\Users\fayaz\Documents\NIDS_IMPLEMENTATION\data\test_data.csv')
    
    # Identify the target column (assuming the last column is the label)
    target_column = 'Label' if 'Label' in test_data.columns else test_data.columns[-1]
    X_test = test_data.drop(target_column, axis=1)
    y_test = test_data[target_column]
    
    print("Starting simulated detection...")
    total_samples = min(100, len(X_test))  # Use a subset for demonstration
    
    detected_attacks = 0
    avg_inference_time = 0
    
    for i in range(total_samples):
        # Get a single sample
        sample = X_test.iloc[[i]]
        
        # Preprocess
        sample_scaled = preprocess_network_data(sample, components)
        
        # Predict
        pred, confidence, inference_time = predict_intrusion(sample_scaled, components)
        
        # Log
        log_detection(pred, confidence, inference_time, sample)
        
        # Track stats
        avg_inference_time += inference_time
        if pred[0] != 0:  # Assuming 0 is normal and other values are attacks
            detected_attacks += 1
        
        # Print progress
        if (i+1) % 10 == 0:
            print(f"Processed {i+1}/{total_samples} samples")
    
    # Print summary
    avg_inference_time /= total_samples
    print("\nSimulation complete!")
    print(f"Total samples processed: {total_samples}")
    print(f"Total attacks detected: {detected_attacks}")
    print(f"Average inference time: {avg_inference_time*1000:.2f} ms")
    print(f"Logs saved to: C:\\Users\\fayaz\\Documents\\NIDS_IMPLEMENTATION\\logs")

if __name__ == "__main__":
    simulate_live_detection()