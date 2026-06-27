import socket        # lets us create a server that accepts connections
import threading      # lets us handle many attackers at the same time
import datetime       # lets us record the exact time of each attack
import json           # lets us save data in a structured format
import os             # lets us create folders and check if files exist

LOG_FILE = "logs/honeypot_log.json"   # where we save attack data
HOST = "0.0.0.0"    # listen on ALL network interfaces (accept from anywhere)
PORT = 2222          # the port we pretend to be SSH on (real SSH is 22)

os.makedirs("logs", exist_ok=True)    # create logs folder if it doesn't exist

def log_attempt(ip, port, username, password):
    """
    This function saves one attack attempt to our log file.
    Every time an attacker tries to log in, we call this function.
    """
    entry = {
        "timestamp": datetime.datetime.now().isoformat(),  # exact time
        "source_ip": ip,        # attacker's IP address
        "source_port": port,    # attacker's port (random number)
        "username": username,   # what username they tried
        "password": password,   # what password they tried
        "attack_type": "ssh_brute_force"   # we label every attempt
    }

    # Open the log file and add one line (JSON format)
    with open(LOG_FILE, "a") as f:          # "a" means append (add to end)
        f.write(json.dumps(entry) + "\n")   # write the data as JSON + newline

    # Also print it in the terminal so we can watch live
    print(f"[ALERT] {ip} tried: {username} / {password}")


def handle_connection(conn, addr):
    """
    This function handles ONE attacker connection.
    It runs in its own thread so we can handle many at once.
    """
    ip, port = addr     # unpack the address tuple into ip and port

    try:
        # Step 1: Send a fake SSH banner
        # Real SSH servers send this line when you first connect.
        # We send the same thing to trick attackers into thinking this is real.
        conn.send(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n")

        # Step 2: Ask for username (like a real login prompt)
        conn.send(b"login: ")

        # Step 3: Wait for the attacker to send a username
        # recv(1024) means: receive up to 1024 bytes of data
        # .decode() converts bytes to a string
        # .strip() removes newlines and spaces at the edges
        username = conn.recv(1024).decode("utf-8", errors="ignore").strip()

        # Step 4: Ask for password
        conn.send(b"Password: ")

        # Step 5: Wait for their password
        password = conn.recv(1024).decode("utf-8", errors="ignore").strip()

        # Step 6: Always deny access — we are a TRAP, not a real server
        conn.send(b"\r\nAccess denied.\r\n")

        # Step 7: Save this attempt to our log
        log_attempt(ip, port, username, password)

    except Exception as e:
        # If anything goes wrong (attacker disconnects, etc.) just skip it
        print(f"[ERROR] from {ip}: {e}")

    finally:
        # Always close the connection at the end
        conn.close()


def start_honeypot():
    """
    This is the main function that starts listening for attackers.
    """
    # Create a TCP socket (the standard type for internet connections)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # This line allows reusing the port immediately after restarting
    # Without it, you'd get "Address already in use" errors
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Bind = attach our socket to our IP and port
    server.bind((HOST, PORT))

    # Start listening. 100 = queue up to 100 connections waiting
    server.listen(100)

    print(f"[*] Honeypot is live on port {PORT}")
    print(f"[*] Saving logs to: {LOG_FILE}")
    print("[*] Waiting for attackers... Press Ctrl+C to stop\n")

    # Infinite loop — keep accepting connections forever
    while True:
        conn, addr = server.accept()   # wait for someone to connect

        # Create a new thread for this attacker so we can handle the next one
        thread = threading.Thread(
            target=handle_connection,   # the function to run in this thread
            args=(conn, addr)           # the arguments to pass to it
        )
        thread.daemon = True    # thread will auto-die when main program exits
        thread.start()          # start the thread


# This means: only run start_honeypot() if we run THIS file directly
# (not if another file imports it)
if __name__ == "__main__":
    start_honeypot()