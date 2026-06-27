import socket
import time
import random

USERNAMES = ["admin", "root", "user", "test", "ubuntu", "pi", "guest", "deploy", "oracle", "postgres"]
PASSWORDS = ["123456", "password", "admin", "root", "12345", "qwerty", "letmein", "monkey", "dragon", "master"]

TARGET_IP = "127.0.0.1"
TARGET_PORT = 2222

def simulate_brute_force(num_attempts=25):
    print(f"[*] Starting simulation: {num_attempts} attempts...")
    for i in range(num_attempts):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((TARGET_IP, TARGET_PORT))
            s.recv(1024)
            s.recv(1024)
            username = random.choice(USERNAMES)
            s.send((username + "\n").encode())
            time.sleep(0.2)
            s.recv(1024)
            password = random.choice(PASSWORDS)
            s.send((password + "\n").encode())
            time.sleep(0.2)
            s.recv(1024)
            s.close()
            print(f"  [{i+1:02d}] Tried: {username} / {password}")
        except Exception as e:
            print(f"  [{i+1:02d}] ERROR: {e}")
        time.sleep(0.5)
    print("[*] Done! Check logs/honeypot_log.json")

if __name__ == "__main__":
    simulate_brute_force(25)
