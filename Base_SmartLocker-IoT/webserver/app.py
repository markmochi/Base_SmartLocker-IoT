
from flask import Flask, render_template, redirect, url_for, jsonify, request
from door_control import DoorController
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

@app.route('/')
def index():
    status = DoorController.get_status()
    return render_template('index.html', status=status)

@app.route('/api/status')
def api_status():
    return jsonify(DoorController.get_status())

@app.route('/api/lock', methods=['POST'])
def api_lock():
    data = request.get_json()
    locked = data.get('locked')
    result = DoorController.set_status(locked)
    return jsonify(result)

@app.route('/lock')
def lock():
    DoorController.set_status(True)
    return redirect(url_for('index'))

@app.route('/unlock')
def unlock():
    DoorController.set_status(False)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
