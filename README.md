# Disa-Server
Disa-Server
Tech Stack
- Python / FastAPI
- Deployment Server - https://replit.com/@yugn27/Disa-Server#main.py
- Production Server - https://fhzjvjrhkf.execute-api.eu-north-1.amazonaws.com/
  
Aws EC2

[Unit]
Description=FastAPI application
After=network.target

[Service]
User=ubuntu
Group=www-data
WorkingDirectory=/backend
ExecStart=python3 -m uvicorn main:app
Restart=always

[Install]
WantedBy=multi-user.target



[Unit]
Description=FastAPI application
After=network.target

[Service]
User=ubuntu
Group=www-data
WorkingDirectory=/backend
ExecStart=/bin/bash -c 'source /backend/venv/bin/activate && exec python3 -m uvicorn main:app'
Restart=always

[Install]
WantedBy=multi-user.target
