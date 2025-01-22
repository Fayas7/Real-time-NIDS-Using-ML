PROJECT: REAL TIME NETWORK INTRUSION DETECTION USING MACHINE LEARNING

view in raw mode if the classification doesn't make sense


/my_project
│
├── /backend
│   ├── main.py                        # FastAPI application entry point; defines API endpoints.
│   ├── model.py                       # Contains functions for loading and using the machine learning model.
│   ├── requirements.txt                # Lists Python dependencies for the backend (e.g., FastAPI, scikit-learn).
│   ├── utils.py                       # (Optional) Utility functions for data processing or other common tasks.
│   ├── /models                        # Directory for storing trained models and encoders.
│   │   ├── model.joblib               # Trained machine learning model.
│   │   └── label_encoder.joblib       # Label encoder for decoding predictions.
│   └── /data                          # Directory for storing raw or processed data files.
│       ├── X_train_processed.csv      # Preprocessed training features.
│       ├── y_train_processed.csv      # Preprocessed training labels.
│       ├── X_test_processed.csv       # Preprocessed test features.
│       └── y_test_processed.csv       # Preprocessed test labels.
│
└── /frontend
    ├── index.html                     # Main HTML file for the web application.
    ├── styles.css                     # CSS file for styling the web application.
    ├── script.js                         # JavaScript file for handling user interactions and API calls.
    └── /assets                        # Directory for static assets (images, fonts, etc.).
        ├── logo.png                   # Logo image for the application.
        └── styles/                    # (Optional) Additional stylesheets.
            └── custom.css             # Custom styles for specific components.




    To create model:run command: python train.py
    To run program and to redirect to FASTAPI:run command:python main.py
