# usage: python3 attack_scan.py <target_ip> <port> <interval_seconds> <duration_seconds> out_log.csv
import requests, time, sys, csv
import socket

if len(sys.argv) < 6:
    print("Usage: attack_scan.py target_ip port interval_sec duration_sec out.csv")
    sys.exit(1)

target = sys.argv[1]
port = int(sys.argv[2])
interval = float(sys.argv[3])
duration = float(sys.argv[4])
out = sys.argv[5]

end = time.time() + duration

# --- New Metrics Counters ---
total_attempts = 0
successful_attempts = 0
failed_attempts = 0
# --- End New Metrics Counters ---

print(f"Starting scan on {target}:{port} for {duration}s, logging to {out}...")

with open(out, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["ts", "success", "status_code", "elapsed_ms", "failure_type"])

    while time.time() < end:
        ts = time.time()
        total_attempts += 1  # Increment total attempts before the try block

        try:
            # Note: The f-string already includes the http:// protocol.
            r = requests.get(f"http://{target}:{port}", timeout=2)

            # Successful connection
            writer.writerow(
                [ts, 1, r.status_code, int(r.elapsed.total_seconds() * 1000), ""]
            )
            successful_attempts += 1  # Increment success counter

        except requests.exceptions.ConnectionError:
            # Connection failed (e.g., MTD hop or closed port)
            writer.writerow([ts, 0, -1, "", "ConnectionError"])
            failed_attempts += 1  # Increment failure counter
        except requests.exceptions.Timeout:
            # Connection timed out
            writer.writerow([ts, 0, -2, "", "Timeout"])
            failed_attempts += 1  # Increment failure counter
        except Exception as e:
            # Any other unexpected exception
            writer.writerow([ts, 0, -3, "", f"Other: {type(e).__name__}"])
            failed_attempts += 1  # Increment failure counter

        f.flush()
        time.sleep(interval)

print(f"Scan finished. Data saved to {out}")

# --- NEW: Summary Output for quick check ---
print("\n--- Summary ---")
print(f"Total Attempts: {total_attempts}")
print(f"Successful Attempts: {successful_attempts}")
print(f"Failed Attempts: {failed_attempts}")
if total_attempts > 0:
    success_rate = successful_attempts / total_attempts
    print(f"Attack Success Rate (P_hit): {success_rate:.4f}")
# --- End Summary Output ---
