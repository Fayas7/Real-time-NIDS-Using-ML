import logging
from fastapi import FastAPI, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from contextlib import asynccontextmanager
import pandas as pd
import joblib
from datetime import datetime, timedelta
import subprocess
import asyncio
import os
from pydantic import BaseModel

@asynccontextmanager
async def lifespan(app: FastAPI):
    logging.info("Starting real-time intrusion detection...")
    yield  # This is where the application runs
    logging.info("Shutting down intrusion detection system...")

app = FastAPI(lifespan=lifespan)

# Ensure the frontend directory exists
if not os.path.exists("frontend"):
    os.makedirs("frontend")

# Mount static files
app.mount("/frontend", StaticFiles(directory="frontend"), name="frontend")

# Set up logging
logging.basicConfig(level=logging.INFO, filename='intrusion_logs.txt', filemode='w', format='%(asctime)s - %(message)s')

# Load the model and label encoder
try:
    MODEL_PATH = os.getenv('MODEL_PATH', 'model.joblib')
    LABEL_ENCODER_PATH = os.getenv('LABEL_ENCODER_PATH', 'label_encoder.joblib')
    model = joblib.load(MODEL_PATH)
    label_encoder = joblib.load(LABEL_ENCODER_PATH)
except FileNotFoundError as e:
    logging.error("Model or label encoder file not found: %s", e)
    raise

# Configuration
INTERFACE_ID = os.getenv('INTERFACE_ID', '18')
START_TIME = datetime.now()
END_TIME = START_TIME + timedelta(minutes=2)

class NetworkPacket(BaseModel):
    src_ip: str
    dst_ip: str
    tcp_src_port: int
    tcp_dst_port: int
    udp_src_port: int
    udp_dst_port: int
    frame_len: int
    frame_time_epoch: float

def is_within_time_window():
    current_time = datetime.now()
    return START_TIME <= current_time <= END_TIME

def capture_and_extract_features():
    command = [
        r"C:\\Program Files\\Wireshark\\tshark.exe",
        '-i', INTERFACE_ID,
        '-T', 'fields',
        '-e', 'ip.src', '-e', 'ip.dst', '-e', 'tcp.srcport',
        '-e', 'tcp.dstport', '-e', 'udp.srcport', '-e', 'udp.dstport',
        '-e', 'frame.len', '-e', 'frame.time_epoch'
    ]
    process = None
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        while True:
            output = process.stdout.readline()
            if output == b"" and process.poll() is not None:
                break
            if output:
                output_features = output.decode('utf-8').strip().split('\t')
                if len(output_features) >= 8:
                    yield output_features
                else:
                    logging.warning("Incomplete packet data: %s", output_features)
    except Exception as e:
        logging.exception("Error during packet capture: %s", e)
    finally:
        if process:
            process.terminate()

def preprocess_features(features):
    try:
        df = pd.DataFrame([features], columns=[
            'ip.src', 'ip.dst', 'tcp.srcport', 'tcp.dstport',
            'udp.srcport', 'udp.dstport', 'frame.len', 'frame.time_epoch'
        ])
        df['frame.len'] = pd.to_numeric(df['frame.len'], errors='coerce')
        return df
    except Exception as e:
        logging.exception("Error during preprocessing: %s", e)
        raise

async def detect_intrusions():
    while True:
        for features in capture_and_extract_features():
            if not is_within_time_window():
                logging.info("Time window ended. Stopping detection.")
                return
            processed_features = preprocess_features(features)
            try:
                prediction = model.predict(processed_features)[0]
                prediction_label = label_encoder.inverse_transform([prediction])[0]
                if prediction_label == 'anomaly':
                    logging.info("Intrusion detected! Features: %s", processed_features.to_dict(orient='records'))
                else:
                    logging.info("Normal traffic detected. Features: %s", processed_features.to_dict(orient='records'))
            except Exception as e:
                logging.exception("Error during prediction: %s", e)
            await asyncio.sleep(0.01)

@app.get("/")
async def read_root():
    return RedirectResponse(url="/frontend/index.html")  # Redirect to index.html

@app.post("/network-data/")
async def receive_network_data(packet: NetworkPacket, background_tasks: BackgroundTasks):
    background_tasks.add_task(process_packet, packet)
    return {"message": "Packet received and is being processed."}

def process_packet(packet: NetworkPacket):
    features = [
        packet.src_ip, packet.dst_ip, packet.tcp_src_port, packet.tcp_dst_port,
        packet.udp_src_port, packet.udp_dst_port, packet.frame_len, packet.frame_time_epoch
    ]
    processed_features = preprocess_features(features)
    try:
        prediction = model.predict(processed_features)[0]
        prediction_label = label_encoder.inverse_transform([prediction])[0]
        if prediction_label == 'anomaly':
            logging.info("Intrusion detected! Features: %s", processed_features.to_dict(orient='records'))
        else:
            logging.info("Normal traffic detected. Features: %s", processed_features.to_dict(orient='records'))
    except Exception as e:
        logging.exception("Error during prediction: %s", e)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)