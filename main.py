import logging
from fastapi import FastAPI, WebSocket, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import threading
import json
import asyncio
import os
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP
from queue import Queue
from typing import Dict, List

# Track WebSocket connections and packet queue
active_connections = []
packet_queue = Queue()
shutdown_event = threading.Event()

class Stats:
    def __init__(self):
        self.total_packets = 0
        self.alerts = 0
        self.start_time = datetime.now()
        self.detection_history = []
        self.alert_history = {}
    
    def add_detection(self, detection):
        self.total_packets += 1
        if detection["prediction_label"] == "anomaly":
            self.alerts += 1
            alert_type = detection["intrusion_type"]
            self.alert_history[alert_type] = self.alert_history.get(alert_type, 0) + 1
            self.detection_history.append(detection)
            if len(self.detection_history) > 100:
                self.detection_history.pop(0)
    
    def get_stats(self):
        uptime = datetime.now() - self.start_time
        return {
            "total_packets": self.total_packets,
            "alerts": self.alerts,
            "uptime": str(uptime),
            "alert_types": self.alert_history,
        }

class IntrusionAnalysis:
    def __init__(self, packet_data: Dict):
        self.packet_data = packet_data
        self.evidence = []
        self.intrusion_type = "Normal"
        self.severity = "Low"
        self.is_anomaly = False
        self.analyze()
    
    def analyze(self):
        # DDoS Attack Detection
        if self.packet_data["frame.len"] > 2000:
            self.evidence.append("Unusually large packet size, potential DDoS attack.")
            self.intrusion_type = "DDoS Attack"
            self.is_anomaly = True
            self.severity = "High"

        # Port Scanning Detection
        if self.packet_data["tcp.dstport"] == 0 and self.packet_data["udp.dstport"] == 0:
            self.evidence.append("Port scanning behavior detected.")
            self.intrusion_type = "Port Scanning"
            self.is_anomaly = True
            self.severity = "Medium"

        # Suspicious Port Access Detection
        suspicious_ports = {21: "FTP", 22: "SSH", 23: "Telnet", 3389: "RDP"}
        if self.packet_data["tcp.dstport"] in suspicious_ports:
            self.evidence.append(f"Attempt to access {suspicious_ports[self.packet_data['tcp.dstport']]} port.")
            self.intrusion_type = f"Suspicious Port Access ({suspicious_ports[self.packet_data['tcp.dstport']]})"
            self.is_anomaly = True
            self.severity = "Medium"

        # Malformed Packet Detection
        if not self.packet_data["ip.src"] or not self.packet_data["ip.dst"]:
            self.evidence.append("Malformed packet detected.")
            self.intrusion_type = "Malformed Packet"
            self.is_anomaly = True
            self.severity = "High"

        # Additional Anomaly Detection
        if self.packet_data["tcp.srcport"] == 80 and self.packet_data["tcp.dstport"] == 443:
            self.evidence.append("HTTP to HTTPS transition detected, potential man-in-the-middle attack.")
            self.intrusion_type = "Man-in-the-Middle Attack"
            self.is_anomaly = True
            self.severity = "High"

        if self.packet_data["frame.len"] < 60:
            self.evidence.append("Unusually small packet size, potential data exfiltration.")
            self.intrusion_type = "Data Exfiltration"
            self.is_anomaly = True
            self.severity = "Medium"
    
    def to_dict(self):
        return {
            "is_anomaly": self.is_anomaly,
            "type": self.intrusion_type,
            "severity": self.severity,
            "evidence": self.evidence
        }

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(level=logging.INFO)
app.state.stats = Stats()

def packet_callback(packet):
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
    sniff(prn=packet_callback, store=0)

@app.get("/api/stats")
async def get_stats():
    return JSONResponse(app.state.stats.get_stats())

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    if not hasattr(app.state, "capture_thread") or not app.state.capture_thread.is_alive():
        app.state.capture_thread = threading.Thread(target=start_packet_capture, daemon=True)
        app.state.capture_thread.start()
    
    try:
        while True:
            if not packet_queue.empty():
                packet_data = packet_queue.get_nowait()
                analysis = IntrusionAnalysis(packet_data)
                message = {
                    "features": packet_data,
                    "prediction_label": "anomaly" if analysis.is_anomaly else "normal",
                    "intrusion_type": analysis.intrusion_type,
                    "severity": analysis.severity,
                    "evidence": analysis.evidence,
                    "timestamp": datetime.now().isoformat()
                }
                app.state.stats.add_detection(message)
                await websocket.send_text(json.dumps(message))
                logging.info(f"Detected: {message}")
            await asyncio.sleep(0.1)
    except Exception as e:
        logging.error(f"WebSocket error: {str(e)}")
    finally:
        active_connections.remove(websocket)

if __name__ == "__main__":
    import uvicorn
    logging.info("Starting NIDS application on http://127.0.0.1:8000")
    uvicorn.run(app, host="127.0.0.1", port=8000)