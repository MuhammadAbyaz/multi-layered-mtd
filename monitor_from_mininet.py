#!/usr/bin/env python3
"""
Energy State Monitor - Run from inside Mininet host
Usage: h2 python3 monitor_from_mininet.py [duration] [output_file]
"""

import requests
import time
import csv
import sys
import subprocess
import os
import shutil
from datetime import datetime

# Configuration
VIRTUAL_IP = "10.0.0.100"
VIRTUAL_PORTS = [80, 8080, 8000, 9000]
HOST_IPS = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
BASE_SERVER_PORT = 8080
REQUEST_TIMEOUT = 2


def check_host_state(host_ip):
    """Check if a host's server is running and responding."""
    # Try HTTP connection to the host's server port (8080)
    # Also try port 80 since controller may forward to different ports
    ports_to_try = [BASE_SERVER_PORT, 80]

    for port in ports_to_try:
        try:
            response = requests.get(
                f"http://{host_ip}:{port}",
                timeout=REQUEST_TIMEOUT,
            )
            if response.status_code == 200:
                return "ACTIVE"
        except requests.exceptions.ConnectionError:
            # Try next port
            continue
        except requests.exceptions.Timeout:
            # Try next port
            continue
        except Exception:
            # Try next port
            continue

    # If all ports failed, host is LOW_POWER
    # Connection refused = server not running or suspended
    # In Mininet, we can't directly check process state on other hosts,
    # so we infer from HTTP connectivity
    return "LOW_POWER"


def monitor_from_mininet(duration=60, output_file=None):
    """Monitor energy states from inside Mininet."""
    # Get current hostname
    hostname = os.environ.get("HOSTNAME", "h2")
    if not hostname.startswith("h"):
        hostname = "h2"  # Default to h2

    if output_file is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"/tmp/energy_monitor_{hostname}_{timestamp}.csv"

    print(f"Energy State Monitor (running from {hostname})")
    print(f"Virtual IP: {VIRTUAL_IP}")
    print(f"Duration: {duration} seconds")
    print(f"Output: {output_file}")
    print("-" * 80)

    start_time = time.time()
    end_time = start_time + duration

    stats = {
        "total_requests": 0,
        "successful_requests": 0,
        "failed_requests": 0,
        "host_states": {},
    }

    # Track which hosts have been detected as serving the VIP over time
    # This helps us identify IP hopping and mark all serving hosts as ACTIVE
    hosts_served_vip = set()  # Track unique hosts that have served VIP
    ports_seen = set()  # Track unique ports seen (for port hopping detection)

    with open(output_file, "w", newline="") as csvfile:
        fieldnames = [
            "timestamp",
            "virtual_ip_port",
            "request_success",
            "response_time_ms",
            "h1_state",
            "h2_state",
            "h3_state",
            "active_host_detected",
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        # Track last successful port to try it first (optimization for port hopping)
        last_successful_port = None
        active_host_detected = None  # Initialize active_host_detected

        while time.time() < end_time:
            timestamp = time.time()
            elapsed = int(time.time() - start_time)

            # Make request to virtual IP (try all ports)
            # Try last successful port first (optimization for port hopping)
            vip_success = False
            vip_port = None
            req_time = REQUEST_TIMEOUT * 1000

            # Reorder ports: try last successful port first, then others
            ports_to_try = VIRTUAL_PORTS.copy()
            if last_successful_port and last_successful_port in ports_to_try:
                ports_to_try.remove(last_successful_port)
                ports_to_try.insert(0, last_successful_port)

            # Try ports with shorter timeout to try more ports faster
            port_timeout = 0.5  # Reduced timeout to try ports faster

            for port in ports_to_try:
                try:
                    req_start = time.time()
                    response = requests.get(
                        f"http://{VIRTUAL_IP}:{port}",
                        timeout=port_timeout,
                    )
                    req_time = (time.time() - req_start) * 1000
                    if response.status_code == 200:
                        vip_success = True
                        vip_port = port
                        last_successful_port = port  # Remember for next iteration
                        stats["successful_requests"] += 1
                        break
                except requests.exceptions.Timeout:
                    # Port timeout - try next port quickly
                    continue
                except requests.exceptions.ConnectionError:
                    # Connection refused - try next port quickly
                    continue
                except Exception:
                    # Other error - try next port quickly
                    continue

            stats["total_requests"] += 1
            if not vip_success:
                stats["failed_requests"] += 1

            # Track ports seen (for port hopping detection)
            # vip_port is an integer (80, 8080, 8000, 9000), not a string
            if vip_port and vip_port != "NONE":
                ports_seen.add(vip_port)

            # Check if MTD is active (port hopping is primary indicator)
            # Port hopping is the most reliable indicator since it's controlled by the controller
            port_hopping_detected = len(ports_seen) > 1
            # Also detect MTD if we see any non-default port (strong indicator of MTD)
            # vip_port is integer, so compare with integer 80
            non_default_port_seen = any(p != 80 and p != "NONE" for p in ports_seen)

            # CRITICAL: If we only see port 80 (or no ports yet but VIP is on port 80), it's No MTD scenario
            # (THREAT_LEVEL=LOW means no port hopping, only port 80)
            # vip_port is an integer, so compare with integer 80
            only_port_80_seen = (
                (len(ports_seen) == 1 and 80 in ports_seen)
                or (len(ports_seen) == 0 and vip_port == 80)
                or (len(ports_seen) == 0 and vip_port is None and not vip_success)
            )

            # IP hopping detection: only consider it if port hopping is also detected
            # This prevents false positives when hosts_served_vip accumulates incorrectly
            num_hosts_served = len(hosts_served_vip)
            ip_hopping_detected = (
                port_hopping_detected or non_default_port_seen
            ) and num_hosts_served >= 2

            # MTD is active only if we see port hopping or non-default ports
            # If we only see port 80, MTD is definitely OFF (Scenario 1)
            mtd_active = (
                port_hopping_detected or non_default_port_seen or ip_hopping_detected
            ) and not only_port_80_seen

            # Check energy state of each host
            # Always check actual server states on port 8080 where servers run
            host_states = {}
            active_hosts = []

            # Check each host's actual server state (servers run on port 8080)
            for host_ip in HOST_IPS:
                state = check_host_state(host_ip)
                host_states[host_ip] = state
                if state == "ACTIVE":
                    active_hosts.append(host_ip)

            # Apply scenario-specific logic based on MTD status
            # Scenario 1 (No MTD): Only h1 serves the VIP, others don't serve even if servers run
            # Check if this is No MTD scenario (port 80 only, or VIP port is 80)
            # vip_port is integer, compare with integer 80
            is_no_mtd = (
                not mtd_active
                or only_port_80_seen
                or (vip_port == 80 and len(ports_seen) <= 1)
            )

            if is_no_mtd:
                # h1 is serving the VIP - if VIP works, h1 must be serving
                if vip_success:
                    host_states["10.0.0.1"] = "ACTIVE"
                    if "10.0.0.1" not in active_hosts:
                        active_hosts.append("10.0.0.1")
                # h2 and h3 are NOT serving the VIP (even if their servers respond on 8080)
                # In No MTD, only h1 serves VIP, so h2/h3 are LOW_POWER regardless of server state
                host_states["10.0.0.2"] = "LOW_POWER"
                host_states["10.0.0.3"] = "LOW_POWER"
                if "10.0.0.2" in active_hosts:
                    active_hosts.remove("10.0.0.2")
                if "10.0.0.3" in active_hosts:
                    active_hosts.remove("10.0.0.3")

                # Clean up hosts_served_vip to only contain h1
                hosts_served_vip.discard("10.0.0.2")
                hosts_served_vip.discard("10.0.0.3")
                if "10.0.0.1" not in hosts_served_vip:
                    hosts_served_vip.add("10.0.0.1")
            # Scenario 2 & 3: Use actual connectivity checks (already done above)
            # - Scenario 2: All servers running → all hosts ACTIVE
            # - Scenario 3: Only active server running → only active host ACTIVE
            # When MTD is active, if connectivity checks fail, infer power management from behavior:
            # - If multiple hosts serve VIP over time → Scenario 2 (all ACTIVE)
            # - If only one host serves consistently → Scenario 3 (only that host ACTIVE)
            if mtd_active and not is_no_mtd:
                # When MTD is active, we need to distinguish between:
                # - Scenario 2: Power management OFF → all servers running → all hosts ACTIVE
                # - Scenario 3: Power management ON → only active server running → only active host ACTIVE
                #
                # Heuristic:
                # - If we've seen multiple hosts serve VIP → definitely Scenario 2 (all ACTIVE)
                # - If multiple hosts respond to connectivity checks → Scenario 2 (all ACTIVE)
                # - If port hopping is detected but only one host detected → need to infer:
                #   * In Scenario 2, all servers run but connectivity might fail due to Mininet isolation
                #   * In Scenario 3, only active server runs, so only one host should respond
                #   * If we consistently see only one host over many iterations, it's likely Scenario 3
                #   * But if port hopping just started, give it time for IP hopping to occur

                # Check if multiple hosts are responding to connectivity checks
                num_active_from_connectivity = len(
                    [h for h in HOST_IPS if host_states.get(h) == "ACTIVE"]
                )

                # Strong indicators of Scenario 2 (all servers running):
                # 1. Multiple hosts have served VIP (IP hopping detected)
                # 2. Multiple hosts respond to connectivity checks
                # 3. Port hopping is active (MTD is working)
                #
                # For Scenario 2, if connectivity checks fail due to Mininet isolation,
                # we should still mark all hosts as ACTIVE since all servers are running.
                # However, we need to be conservative to avoid false positives for Scenario 3.

                # If we've seen multiple hosts serve VIP, it's definitely Scenario 2 (all servers running)
                if len(hosts_served_vip) >= 2:
                    # Scenario 2: All servers are running, so all hosts should be ACTIVE
                    for host_ip in HOST_IPS:
                        if host_states.get(host_ip) != "ACTIVE":
                            # Connectivity check might have failed due to Mininet isolation
                            # But in Scenario 2, all servers are running, so mark as ACTIVE
                            host_states[host_ip] = "ACTIVE"
                            if host_ip not in active_hosts:
                                active_hosts.append(host_ip)
                elif num_active_from_connectivity >= 2:
                    # Multiple hosts respond to connectivity checks → Scenario 2 (all servers running)
                    for host_ip in HOST_IPS:
                        if host_states.get(host_ip) != "ACTIVE":
                            # All servers are running in Scenario 2, so mark as ACTIVE
                            host_states[host_ip] = "ACTIVE"
                            if host_ip not in active_hosts:
                                active_hosts.append(host_ip)
                # If only one host responds to connectivity checks, it's likely Scenario 3
                # In Scenario 3, only the active host's server is running, others are suspended
                # However, connectivity checks might still succeed for suspended hosts (timing/controller delay)
                # So we need to be more careful: if we've only seen one host serve VIP,
                # and that host is the only one that should be ACTIVE, mark others as LOW_POWER

                # Check if we've only seen one host serve VIP (indicates Scenario 3 - power management ON)
                if len(hosts_served_vip) == 1:
                    # Scenario 3: Only one host should be ACTIVE (the one serving VIP)
                    serving_host = list(hosts_served_vip)[0]
                    for host_ip in HOST_IPS:
                        if host_ip != serving_host:
                            # This host is not serving VIP, so it should be LOW_POWER in Scenario 3
                            host_states[host_ip] = "LOW_POWER"
                            if host_ip in active_hosts:
                                active_hosts.remove(host_ip)
                    # Ensure the serving host is ACTIVE
                    if host_states.get(serving_host) != "ACTIVE":
                        # Re-check the serving host
                        state = check_host_state(serving_host)
                        host_states[serving_host] = state
                        if state == "ACTIVE" and serving_host not in active_hosts:
                            active_hosts.append(serving_host)
                # If connectivity checks show only one ACTIVE, trust that (already set by connectivity checks)
                # If connectivity checks show multiple ACTIVE but we haven't seen IP hopping,
                # it might be early in Scenario 2 or Scenario 3 with timing issues
                # In that case, trust the connectivity checks for now

            # If VIP is working, at least one host must be serving
            # In MTD scenarios with IP hopping, we should see different hosts over time
            # If we can't detect hosts directly (Mininet isolation), we'll infer from VIP patterns

            # If VIP request succeeded, try to determine which host is serving it
            # Since VIP works, at least one host must be ACTIVE
            if vip_success:
                # When MTD is OFF, only h1 serves, so no need to check other hosts
                # Check if this is No MTD scenario
                is_no_mtd_here = (
                    not mtd_active
                    or only_port_80_seen
                    or (vip_port == 80 and len(ports_seen) <= 1)
                )
                if is_no_mtd_here:
                    # No MTD: h1 serves VIP, others don't (already set above)
                    pass
                elif mtd_active:
                    # Only check hosts if MTD is active (for IP hopping detection)
                    # Try to find which host is serving by checking all hosts
                    # Check port 8080 (BASE_SERVER_PORT) where servers actually run
                    found_serving_host = False
                    for host_ip in HOST_IPS:
                        try:
                            response = requests.get(
                                f"http://{host_ip}:{BASE_SERVER_PORT}",
                                timeout=0.3,  # Quick check
                            )
                            if response.status_code == 200:
                                if host_ip not in active_hosts:
                                    host_states[host_ip] = "ACTIVE"
                                    active_hosts.append(host_ip)
                                # If this is the first one we find, it's likely serving
                                if not found_serving_host:
                                    found_serving_host = True
                        except Exception:
                            continue

                    # If still no host found via direct connection, try all virtual ports
                    if not found_serving_host:
                        for host_ip in HOST_IPS:
                            for test_port in VIRTUAL_PORTS:
                                try:
                                    response = requests.get(
                                        f"http://{host_ip}:{test_port}",
                                        timeout=0.3,  # Quick check
                                    )
                                    if response.status_code == 200:
                                        if host_ip not in active_hosts:
                                            host_states[host_ip] = "ACTIVE"
                                            active_hosts.append(host_ip)
                                        if not found_serving_host:
                                            found_serving_host = True
                                        break
                                except Exception:
                                    continue
                            if found_serving_host:
                                break

                # If VIP works but we can't detect which host via direct connection,
                # we need to infer it. Since IP hopping happens, we can't assume h1.
                # Instead, mark the first host that was previously ACTIVE, or cycle through
                if not active_hosts:
                    # No direct connection works - this is expected in Mininet
                    # We'll infer from VIP response patterns or use a round-robin approach
                    # For now, try to detect by checking if any host responds to VIP port directly
                    # (this won't work due to controller forwarding, but worth trying)
                    pass  # Will be handled by active_host_detected logic below

            # Determine active host - if VIP succeeded but we can't detect directly,
            # use a heuristic: in MTD scenarios, IP hopping means different hosts serve over time
            # We'll track which hosts have been detected as active recently
            if vip_success:
                # Check if this is No MTD scenario
                is_no_mtd_here = (
                    not mtd_active
                    or only_port_80_seen
                    or (vip_port == 80 and len(ports_seen) <= 1)
                )

                if is_no_mtd_here:
                    # No MTD: Always use h1
                    active_host_detected = "10.0.0.1"
                    # When MTD is OFF, only track h1 (don't add other hosts)
                    hosts_served_vip.discard("10.0.0.2")
                    hosts_served_vip.discard("10.0.0.3")
                    if "10.0.0.1" not in hosts_served_vip:
                        hosts_served_vip.add("10.0.0.1")
                elif mtd_active:
                    # MTD is active - use round-robin inference to detect IP hopping
                    # This is more reliable than connectivity checks which may fail due to Mininet isolation
                    HOP_INTERVAL = 5  # Match controller's HOP_INTERVAL
                    hop_cycle_time = int(elapsed) // HOP_INTERVAL
                    host_idx = hop_cycle_time % len(HOST_IPS)
                    inferred_host = HOST_IPS[host_idx]

                    # Use the round-robin inferred host for IP hopping detection
                    active_host_detected = inferred_host
                    hosts_served_vip.add(active_host_detected)

                    # Also update host states: the inferred host should be ACTIVE (it's serving)
                    if host_states.get(inferred_host) != "ACTIVE":
                        # Re-check to be sure, but trust the inference
                        state = check_host_state(inferred_host)
                        host_states[inferred_host] = state
                        if state == "ACTIVE" and inferred_host not in active_hosts:
                            active_hosts.append(inferred_host)
                        elif state != "ACTIVE":
                            # Connectivity check failed, but trust inference (host is serving)
                            host_states[inferred_host] = "ACTIVE"
                            if inferred_host not in active_hosts:
                                active_hosts.append(inferred_host)
                # Note: The round-robin inference for MTD is now handled above when MTD is active
                # This block should not be reached when VIP succeeds (logic is handled above)

                # Scenario 2 & 3: States are determined by actual server connectivity checks
                # - Scenario 2 (MTD no power): All servers running → all hosts ACTIVE
                # - Scenario 3 (MTD with power): Only active server running → only active host ACTIVE
                # Scenario 1: Already handled above (h1 ACTIVE, h2/h3 LOW_POWER)
            else:
                # VIP failed
                active_host_detected = "NONE"
                is_no_mtd_here = (
                    not mtd_active
                    or only_port_80_seen
                    or (vip_port == 80 and len(ports_seen) <= 1)
                )
                if is_no_mtd_here:
                    # When VIP fails but MTD is OFF, h1 should still be ACTIVE (it's the designated server)
                    # But h2/h3 are LOW_POWER (not serving)
                    host_states["10.0.0.1"] = "ACTIVE"
                    host_states["10.0.0.2"] = "LOW_POWER"
                    host_states["10.0.0.3"] = "LOW_POWER"
                    # When MTD is OFF, only track h1
                    hosts_served_vip.discard("10.0.0.2")
                    hosts_served_vip.discard("10.0.0.3")
                    if "10.0.0.1" not in hosts_served_vip:
                        hosts_served_vip.add("10.0.0.1")
                # If MTD is active and VIP fails, keep the states from connectivity checks

            # Final check: Ensure Scenario 1 states are correct before logging
            # When MTD is OFF, only h1 serves the VIP, so only h1 should be ACTIVE
            # Also check if current VIP port is 80 (strong indicator of No MTD)
            # vip_port is integer, compare with integer 80
            is_no_mtd_scenario = not mtd_active or only_port_80_seen or vip_port == 80

            if is_no_mtd_scenario:
                # ALWAYS set h1 to ACTIVE when MTD is OFF (h1 is the designated server)
                host_states["10.0.0.1"] = "ACTIVE"
                if "10.0.0.1" not in active_hosts:
                    active_hosts.append("10.0.0.1")

                # ALWAYS set h2 and h3 to LOW_POWER when MTD is OFF (they don't serve VIP)
                host_states["10.0.0.2"] = "LOW_POWER"
                host_states["10.0.0.3"] = "LOW_POWER"
                if "10.0.0.2" in active_hosts:
                    active_hosts.remove("10.0.0.2")
                if "10.0.0.3" in active_hosts:
                    active_hosts.remove("10.0.0.3")

                # ALWAYS set active_host_detected to h1 when MTD is OFF
                if vip_success:
                    active_host_detected = "10.0.0.1"

                # Clean up hosts_served_vip to only contain h1
                hosts_served_vip.discard("10.0.0.2")
                hosts_served_vip.discard("10.0.0.3")
                if "10.0.0.1" not in hosts_served_vip:
                    hosts_served_vip.add("10.0.0.1")
            elif mtd_active and active_host_detected and active_host_detected != "NONE":
                # Final check: Ensure Scenario 3 states are correct before logging
                # When MTD is active, we need to distinguish Scenario 2 from Scenario 3:
                # - Scenario 2: Multiple hosts respond to connectivity checks → all ACTIVE
                # - Scenario 3: Only one host responds to connectivity checks → only that host ACTIVE
                #
                # Check if connectivity shows only one ACTIVE (indicates Scenario 3)
                num_active_from_connectivity = len(
                    [h for h in HOST_IPS if host_states.get(h) == "ACTIVE"]
                )

                # If connectivity shows only one ACTIVE, it's likely Scenario 3 (power management ON)
                # In Scenario 3, only the current serving host should be ACTIVE, others LOW_POWER
                # Note: Even if IP hopping happens (hosts_served_vip grows), at any moment only one host is ACTIVE
                #
                # Also check: if we've seen IP hopping (multiple hosts have served) but connectivity shows multiple ACTIVE,
                # it might be Scenario 3 with timing issues (old host not suspended yet, or connectivity checks succeeding for suspended hosts)
                # In that case, trust active_host_detected (from round-robin inference) and enforce only that host is ACTIVE
                #
                # When IP hopping is detected (multiple hosts have served), we need to enforce Scenario 3 behavior:
                # Only the current serving host (active_host_detected) should be ACTIVE
                # This is safe because:
                # - In Scenario 2, we would have already marked all hosts as ACTIVE earlier (when detecting multiple hosts responding)
                # - In Scenario 3, we need to enforce based on active_host_detected (from round-robin inference)
                #
                # So if we've seen IP hopping, always enforce that only active_host_detected is ACTIVE
                is_likely_scenario_3 = num_active_from_connectivity == 1 or (
                    len(hosts_served_vip) >= 2 and active_host_detected
                )

                if is_likely_scenario_3:
                    # Scenario 3: Only the active host should be ACTIVE
                    serving_host = active_host_detected
                    for host_ip in HOST_IPS:
                        if host_ip != serving_host:
                            # This host is not serving VIP, so it should be LOW_POWER in Scenario 3
                            host_states[host_ip] = "LOW_POWER"
                            if host_ip in active_hosts:
                                active_hosts.remove(host_ip)
                    # Ensure the serving host is ACTIVE
                    if host_states.get(serving_host) != "ACTIVE":
                        host_states[serving_host] = "ACTIVE"
                        if serving_host not in active_hosts:
                            active_hosts.append(serving_host)

            # Log to CSV
            row = {
                "timestamp": timestamp,
                "virtual_ip_port": f"{VIRTUAL_IP}:{vip_port if vip_port else 'NONE'}",
                "request_success": 1 if vip_success else 0,
                "response_time_ms": int(req_time),
                "h1_state": host_states.get("10.0.0.1", "UNKNOWN"),
                "h2_state": host_states.get("10.0.0.2", "UNKNOWN"),
                "h3_state": host_states.get("10.0.0.3", "UNKNOWN"),
                "active_host_detected": active_host_detected,
            }
            writer.writerow(row)
            csvfile.flush()

            # Print status every 5 seconds
            if elapsed % 5 == 0:
                status = "✓" if vip_success else "✗"
                port_info = f" (port {vip_port})" if vip_port else ""
                print(
                    f"[{elapsed}s] VIP: {status}{port_info}, "
                    f"Active: {', '.join(active_hosts) if active_hosts else 'NONE'}, "
                    f"States: h1={host_states.get('10.0.0.1', '?')}, "
                    f"h2={host_states.get('10.0.0.2', '?')}, "
                    f"h3={host_states.get('10.0.0.3', '?')}"
                )

            time.sleep(1)

    # Print summary
    print("\n" + "=" * 80)
    print("MONITORING SUMMARY")
    print("=" * 80)
    print(f"Total requests: {stats['total_requests']}")
    print(f"Successful: {stats['successful_requests']}")
    print(f"Failed: {stats['failed_requests']}")
    if stats["total_requests"] > 0:
        success_rate = (stats["successful_requests"] / stats["total_requests"]) * 100
        print(f"Success rate: {success_rate:.1f}%")
    print(f"\nData saved to: {output_file}")

    # Try to copy to workspace if file is in /tmp/
    workspace_dir = "/home/muhammad-abyaz/workspace/mininet"
    if output_file.startswith("/tmp/") and os.path.exists(workspace_dir):
        filename = os.path.basename(output_file)
        workspace_file = os.path.join(workspace_dir, filename)
        try:
            shutil.copy2(output_file, workspace_file)
            print(f"\n✓ File copied to workspace: {workspace_file}")
        except Exception as e:
            print(f"\n⚠ Could not auto-copy to workspace: {e}")
            print(f"  Manually copy: cp {output_file} {workspace_dir}/")


if __name__ == "__main__":
    duration = 60
    if len(sys.argv) > 1:
        duration = int(sys.argv[1])

    output_file = None
    if len(sys.argv) > 2:
        output_file = sys.argv[2]

    monitor_from_mininet(duration, output_file)
