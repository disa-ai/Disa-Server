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









Deploying a FastAPI application to an Amazon EC2 instance with API Gateway involves several steps. Here's a step-by-step guide to help you through the process:

### Step 1: Set Up Your EC2 Instance

1. **Launch an EC2 Instance:**
   - Go to the AWS Management Console.
   - Navigate to EC2 under the Services menu.
   - Click "Launch Instance" and follow the wizard to select an AMI (Ubuntu is recommended), instance type, and configure your instance details.
   - Make sure to create or select a security group that allows inbound traffic on the port you'll use for FastAPI (e.g., port 8000).
   - Download the key pair (.pem file) if you haven’t already, and keep it secure.

2. **Connect to Your EC2 Instance:**
   - Use SSH to connect to your instance. Open your terminal and run:
     ```bash
     ssh -i "your-key.pem" ubuntu@your-ec2-public-dns
     ```

### Step 2: Prepare the EC2 Instance

1. **Update and Upgrade the System:**
   ```bash
   sudo apt update
   sudo apt upgrade -y
   ```

2. **Install Python and Pip:**
   ```bash
   sudo apt install python3 python3-pip python3-venv nginx -y
   ```

3. **Install and Configure FastAPI Dependencies:**
   - Navigate to your project directory or create a new one.
   - Create a virtual environment and activate it:
     ```bash
     python3 -m venv env
     source env/bin/activate
     ```
   - Install FastAPI and an ASGI server (e.g., `uvicorn`):
     ```bash
     pip install -r requirements.txt
     ```
   - Deploy your FastAPI application code to the EC2 instance (e.g., using `scp` or by cloning from a version control system).
  
   - Cretae file
   - nano main.py
   - nano smpt.py
   - Replace the keys in main.py

### Step 3: Run FastAPI with Uvicorn

1. **Test FastAPI Locally:**
   - Run your FastAPI application to ensure it works:
     ```bash
     uvicorn main:app --host 0.0.0.0 --port 8000
     ```
   - You should be able to access the API at `http://your-ec2-public-dns:8000`.

2. **Configure a Process Manager:**
   - Install `supervisor` or `systemd` to manage your FastAPI application.
     For example, with `supervisor`:
     ```bash
     sudo apt install supervisor
     ```
   - Create a configuration file for your FastAPI application:
     ```bash
     sudo nano /etc/supervisor/conf.d/fastapi.conf
     ```
     Add the following content:
     ```ini
     [program:fastapi]
     command=/path/to/venv/bin/uvicorn your_app:app --host 0.0.0.0 --port 8000
     directory=/path/to/your/app
     autostart=true
     autorestart=true
     stderr_logfile=/var/log/fastapi.err.log
     stdout_logfile=/var/log/fastapi.out.log
     ```
   - Update `supervisor` and start your FastAPI application:
     ```bash
     sudo supervisorctl reread
     sudo supervisorctl update
     sudo supervisorctl start fastapi
     ```

### Step 4: Set Up API Gateway

1. **Create a New API in API Gateway:**
   - Go to the API Gateway service in the AWS Management Console.
   - Click "Create API" and choose "HTTP API" or "REST API" depending on your needs.
   - Follow the steps to create a new API.

2. **Configure the API Gateway:**
   - For HTTP API:
     - Set up an integration with HTTP by specifying your EC2 instance’s public DNS and port (e.g., `http://your-ec2-public-dns:8000`).
     - Create a route that maps to the HTTP method you want to use (e.g., `GET`).
     - Deploy your API and note the Invoke URL.

3. **Configure Security and CORS:**
   - Ensure that your API Gateway setup includes any necessary CORS configuration.
   - Set up appropriate security measures like API keys or IAM roles if needed.

### Step 5: Test Your API Gateway

1. **Access Your FastAPI Application Through API Gateway:**
   - Use the Invoke URL provided by API Gateway to make requests.
   - Ensure that requests are correctly routed to your FastAPI application and responses are returned as expected.

2. **Monitor and Debug:**
   - Check logs in CloudWatch (for API Gateway and EC2) to monitor and debug any issues.
   - Ensure that both your EC2 instance and API Gateway configurations are working seamlessly.

### Additional Tips

- **Use Domain Names:** Consider setting up a custom domain name using Route 53 and configuring SSL certificates for secure HTTPS connections.
- **Automate Deployment:** Use tools like AWS CodeDeploy or CI/CD pipelines for more automated deployments and updates.

This guide covers the essential steps to deploy a FastAPI application with Amazon EC2 and API Gateway. If you run into any issues or need more detailed instructions on specific steps, feel free to ask!
