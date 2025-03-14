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
from starlette.websockets import WebSocketDisconnect, WebSocketState

# Add WebSocket connections store
active_connections = []
packet_queue = Queue()

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

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
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

def start_packet_capture():
    """Start packet capture in a separate thread"""
    try:
        sniff(prn=packet_callback, store=0)
    except Exception as e:
        logging.error(f"Packet capture error: {e}")

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
            if websocket.client_state == WebSocketState.DISCONNECTED:
                break
            
            try:
                # Process packets from the queue
                if not packet_queue.empty():
                    packet_data = packet_queue.get_nowait()
                    message = {
                        "features": packet_data,
                        "prediction_label": "normal" if packet_data["frame.len"] < 1000 else "anomaly",
                        "timestamp": datetime.now().isoformat()
                    }
                    await websocket.send_text(json.dumps(message))
                    logging.info(f"Packet sent: {packet_data['ip.src']} -> {packet_data['ip.dst']}")
                
                await asyncio.sleep(0.1)  # Small delay to prevent CPU overload
                
            except Exception as e:
                logging.error(f"Error processing packet: {e}")
                continue
                
    except WebSocketDisconnect:
        logging.info("WebSocket disconnected")
    finally:
        if websocket in active_connections:
            active_connections.remove(websocket)
        await websocket.close()
        logging.info("WebSocket connection closed")

# Mount static files AFTER all routes are defined
app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")

if __name__ == "__main__":
    import uvicorn
    logging.info("Starting NIDS application...")
    uvicorn.run(app, host="127.0.0.1", port=8000)
