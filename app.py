from flask import Flask, jsonify, render_template
import json
import subprocess
import os
import threading
import time

app = Flask(__name__)

# Function to start the C++ executable if it's not already running
def start_cpp_executable():
    if not os.path.exists("ass.exe"):
        print("Error: C++ executable (ass.exe) not found.")
        return
    # Run the C++ executable in the background
    subprocess.Popen("ass.exe", shell=True)

# Function to read metrics data from JSON file
def read_metrics():
    try:
        with open("network_metrics.json", "r") as file:
            data = json.load(file)
        return data
    except (FileNotFoundError, json.JSONDecodeError):
        return {"globalMetrics": {}, "connections": []}

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/metrics')
def metrics():
    data = read_metrics()
    return jsonify(data)

if __name__ == '__main__':
    # Start the C++ executable in a separate thread
    cpp_thread = threading.Thread(target=start_cpp_executable)
    cpp_thread.start()

    # Start the Flask application
    app.run(debug=True)
