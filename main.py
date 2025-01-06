# main.py

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import pandas as pd
import joblib
from model import load_model  # Assuming you have a function to load your model

app = FastAPI()

# Load the trained model and label encoder
model = load_model("model.joblib")
label_encoder = load_model("label_encoder.joblib")

# Define a request model for incoming data
class PredictionRequest(BaseModel):
    features: list  # This should match the feature set used for training

@app.get("/")
async def read_root():
    """Root endpoint that returns a welcome message."""
    return {"message": "Welcome to the Network Intrusion Detection System API!"}

@app.post("/predict")
async def predict(request: PredictionRequest):
    """Endpoint to make predictions."""
    try:
        # Convert the incoming features to a DataFrame
        input_data = pd.DataFrame([request.features])
        
        # Make predictions
        predictions = model.predict(input_data)
        
        # Decode the predictions back to original labels
        predicted_labels = label_encoder.inverse_transform(predictions)
        
        return {"predictions": predicted_labels.tolist()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)