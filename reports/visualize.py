import json
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from collections import Counter
from datetime import datetime
import os

LOG_FILE = "logs/honeypot_log.json"
OUTPUT_DIR = "reports"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def load_data():
    with open(LOG_FILE, "r") as f:
        logs = [json.loads(line) for line in f if line.strip()]
    df = pd.DataFrame(logs)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["minute"] = df["timestamp"].dt.floor("1min")
    return df

def generate_charts():
    print("[*] Loading data...")
    df = load_data()
    print(f"[*] Found {len(df)} log entries")

    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle(f"Honeypot Attack Analysis — {len(df)} attempts", fontsize=14, fontweight="bold")

    # Chart 1: Top IPs
    top_ips = df["source_ip"].value_counts().head(8)
    axes[0,0].bar(range(len(top_ips)), top_ips.values, color="#E53935")
    axes[0,0].set_xticks(range(len(top_ips)))
    axes[0,0].set_xticklabels(top_ips.index, rotation=30, ha="right", fontsize=8)
    axes[0,0].set_title("Top Attacking IPs")
    axes[0,0].set_ylabel("Attempts")

    # Chart 2: Top usernames
    top_users = df["username"].value_counts().head(10)
    axes[0,1].barh(range(len(top_users)), top_users.values, color="#1565C0")
    axes[0,1].set_yticks(range(len(top_users)))
    axes[0,1].set_yticklabels(top_users.index, fontsize=9)
    axes[0,1].invert_yaxis()
    axes[0,1].set_title("Most Targeted Usernames")

    # Chart 3: Timeline
    timeline = df.groupby("minute").size()
    axes[1,0].plot(timeline.index, timeline.values, color="#1565C0", linewidth=2)
    axes[1,0].fill_between(timeline.index, timeline.values, alpha=0.2, color="#1565C0")
    axes[1,0].set_title("Attack Timeline")
    axes[1,0].set_ylabel("Attacks per minute")
    axes[1,0].tick_params(axis="x", rotation=30)

    # Chart 4: Password distribution
    top_passwords = df["password"].value_counts().head(8)
    axes[1,1].bar(range(len(top_passwords)), top_passwords.values, color="#6A1B9A")
    axes[1,1].set_xticks(range(len(top_passwords)))
    axes[1,1].set_xticklabels(top_passwords.index, rotation=30, ha="right", fontsize=8)
    axes[1,1].set_title("Most Tried Passwords")
    axes[1,1].set_ylabel("Count")

    plt.tight_layout()
    output_path = f"{OUTPUT_DIR}/attack_analysis.png"
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[*] Chart saved to: {output_path}")
    print("[*] Done! Open reports/attack_analysis.png to view it.")

if __name__ == "__main__":
    generate_charts()
