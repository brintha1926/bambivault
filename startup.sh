#!/bin/bash
echo "Installing dependencies..."
pip install -r requirements.txt

echo "Running migrations..."
flask db upgrade || true

echo "Starting Gunicorn server..."
gunicorn -b 0.0.0.0:8000 -w 4 app:app
