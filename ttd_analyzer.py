import pandas as pd
import sys
import os


def calculate_ttd(log_file):
    """
    Calculates the Time-to-Disruption (TTD) from a log file.
    TTD = (Timestamp of Last Success) - (Timestamp of First Success)
    """
    if not os.path.exists(log_file):
        print(f"Error: Log file not found at {log_file}")
        return None, None

    # Load data, skipping the header line and defining all five columns
    try:
        df = pd.read_csv(
            log_file,
            skiprows=1,  # Skip the actual header line
            header=None,  # Tell pandas there is no header row after skipping
            # Define all 5 columns present in your file
            names=["ts", "success", "status_code", "elapsed_ms", "failure_type"],
            skipinitialspace=True,
        )
    except pd.errors.EmptyDataError:
        print(f"Warning: Log file {log_file} is empty.")
        return None, None
    except Exception as e:
        # Catch other errors, like not enough columns
        print(f"Error reading {log_file}: {e}")
        return None, None

    # 1. Find all successful connection attempts (success == 1)
    successful_attempts = df[df["success"] == 1].copy()

    if successful_attempts.empty:
        print(f"  Result: 🚫 No successful connections found in {log_file}.")
        return 0, 0

    # 2. Get the timestamps for the first and last successful attempt
    first_success_ts = successful_attempts["ts"].min()
    last_success_ts = successful_attempts["ts"].max()

    # 3. Calculate TTD
    ttd = last_success_ts - first_success_ts

    # 4. Count the number of successful probes (Connection Resilience)
    successful_probe_count = len(successful_attempts)

    return ttd, successful_probe_count


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python ttd_analyzer.py <log_file_1> [log_file_2] ...")
        sys.exit(1)

    all_ttds = {}
    for log_file in sys.argv[1:]:
        print(f"\n--- Analyzing {log_file} ---")
        ttd, probe_count = calculate_ttd(log_file)

        if ttd is not None:
            all_ttds[log_file] = ttd
            print(f"  Time-to-Disruption (TTD): {ttd:.4f} seconds")
            print(f"  Successful Probes: {probe_count}")

    if all_ttds:
        print("\n=== SUMMARY ===")
        avg_ttd = sum(all_ttds.values()) / len(all_ttds)
        print(f"Average TTD across all analyzed logs: {avg_ttd:.4f} seconds")
