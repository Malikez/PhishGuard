## Description
PhishGuard: Phishing URL Detection Web Application
PhishGuard is a full-stack web application that detects phishing URLs using a machine learning model (Random Forest). It offers both a user-friendly frontend interface and an AI-powered backend service.

You can choose to:

Run only the backend to test the core functionality, or

Run both the frontend and backend for the complete experience.

## Repo links
Frontend repo here → https://github.com/preete126/phishGuard
Backend repo here → https://github.com/malikez/PhishGuard

## Project Structure
'''
PhishGuard/
│
├── PhishGuard backend/               # Python-based Flask backend
│   ├── app.py
│   ├── analyzer.py
│   ├── model/
│   └── requirements.txt   # List of Python dependencies
│
└── phisguard/             # Frontend built with Vue.js
    ├── src/
    ├── public/
    └── package.json
'''

## Getting Started

Prerequisites
Before running the application, ensure you have the following installed:

Node.js & npm (for the frontend)

Python 3.10 or later (for the backend)

pip (Python package installer)


## Running the Backend (Python + Flask)
Navigate to the backend folder:
open the terminal
cd PhishGuard Backend
Install dependencies using requirements.txt:


Create a virtual environment (recommended):

python -m venv venv
source venv/bin/activate       # On Linux/Mac
venv\Scripts\activate          # On Windows
Then install all required packages:


pip install -r requirements.txt
Run the Flask server:

python app.py
If successful, your backend will be running at:
http://127.0.0.1:5004


## Running the Frontend (Vue.js)
Navigate to the frontend folder:
Open the Terminal
cd phisguard

Install Node.js dependencies:


npm install
Start the frontend server:


npm run dev
Once running, visit:
http://localhost:3000

## Note
Important: The frontend needs the backend to be running at http://127.0.0.1:5004. Without it, the URL analysis will not work and return errors.

