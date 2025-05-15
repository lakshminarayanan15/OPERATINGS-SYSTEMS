# Enhanced Phishing Detection System

A modern web application for detecting potential phishing attempts while monitoring system metrics. The application features a beautiful UI with real-time graphs and system monitoring capabilities.

## Features

- URL analysis for phishing detection
- Real-time system metrics monitoring (CPU, Memory, Disk usage)
- Interactive graphs showing system metrics trends
- Risk score calculation based on multiple indicators
- Modern and responsive UI

## Prerequisites

- Python 3.7 or higher
- pip (Python package manager)

## Installation

1. Clone this repository
2. Create a virtual environment (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Start the Flask application:
   ```bash
   python app.py
   ```
2. Open your web browser and navigate to `http://localhost:5000`
3. Enter a URL in the input field and click "Analyze" to check for potential phishing attempts
4. Monitor system metrics in real-time through the interactive graphs

## How it Works

The application uses multiple indicators to detect potential phishing attempts:
- Suspicious TLD detection
- IP address usage
- Suspicious port numbers
- System resource anomalies

The risk score is calculated based on these indicators and system metrics, providing a comprehensive analysis of potential threats.

## Contributing

Feel free to submit issues and enhancement requests! 