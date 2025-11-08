#!/usr/bin/env python3
"""
Analyze and compare energy consumption across MTD scenarios
"""

import csv
import sys
from collections import defaultdict


def analyze_scenario(filename):
    """Analyze a single scenario CSV file."""
    if not filename or not os.path.exists(filename):
        return None

    stats = {
        "total_samples": 0,
        "successful_requests": 0,
        "failed_requests": 0,
        "host_states": defaultdict(lambda: {"ACTIVE": 0, "LOW_POWER": 0, "UNKNOWN": 0}),
        "ports_used": set(),
        "active_hosts_tracked": defaultdict(int),
    }

    with open(filename, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            stats["total_samples"] += 1

            # Request success
            if row.get("request_success") == "1":
                stats["successful_requests"] += 1
            else:
                stats["failed_requests"] += 1

            # Port used
            vip_port = row.get("virtual_ip_port", "").split(":")[-1]
            if vip_port != "NONE":
                stats["ports_used"].add(vip_port)

            # Host states
            for host in ["h1_state", "h2_state", "h3_state"]:
                state = row.get(host, "UNKNOWN")
                host_key = host.replace("_state", "")
                stats["host_states"][host_key][state] += 1

            # Active host detected
            active = row.get("active_host_detected", "NONE")
            if active != "NONE":
                stats["active_hosts_tracked"][active] += 1

    return stats


def print_comparison(scenario_files):
    """Print comparison of all scenarios."""
    import os

    print("=" * 80)
    print("ENERGY CONSUMPTION COMPARISON ANALYSIS")
    print("=" * 80)
    print()

    scenario_names = {
        "scenario1_no_mtd.csv": "No MTD",
        "scenario2_mtd_no_power.csv": "MTD without Power Management",
        "scenario2_mtd_power.csv": "MTD with Power Management",
    }

    all_stats = {}

    for filename in scenario_files:
        if not os.path.exists(filename):
            print(f"⚠️  {filename}: File not found")
            continue

        stats = analyze_scenario(filename)
        if stats:
            all_stats[filename] = stats
            name = scenario_names.get(filename, filename)

            print(f"{name}")
            print("-" * 80)
            print(f"  Total samples: {stats['total_samples']}")
            print(
                f"  Successful requests: {stats['successful_requests']} ({stats['successful_requests']/stats['total_samples']*100:.1f}%)"
            )
            print(
                f"  Failed requests: {stats['failed_requests']} ({stats['failed_requests']/stats['total_samples']*100:.1f}%)"
            )
            print(f"  VIP ports used: {sorted(stats['ports_used'])}")
            print()

            # Calculate energy efficiency
            total_host_time = stats["total_samples"] * 3  # 3 hosts
            total_low_power_time = sum(
                stats["host_states"][host]["LOW_POWER"] for host in ["h1", "h2", "h3"]
            )
            energy_efficiency = (
                (total_low_power_time / total_host_time * 100)
                if total_host_time > 0
                else 0
            )

            print(f"  Energy Efficiency (LOW_POWER %): {energy_efficiency:.1f}%")
            print()

            print("  Host Energy States:")
            for host in ["h1", "h2", "h3"]:
                host_stat = stats["host_states"][host]
                total = sum(host_stat.values())
                if total > 0:
                    active_pct = (host_stat["ACTIVE"] / total) * 100
                    low_power_pct = (host_stat["LOW_POWER"] / total) * 100
                    print(
                        f"    {host}: ACTIVE={active_pct:.1f}%, LOW_POWER={low_power_pct:.1f}% "
                        f"(ACTIVE: {host_stat['ACTIVE']}, LOW_POWER: {host_stat['LOW_POWER']})"
                    )

            print()
            print("  Active Host Distribution:")
            for host_ip, count in sorted(stats["active_hosts_tracked"].items()):
                pct = (count / stats["total_samples"]) * 100
                print(f"    {host_ip}: {count} times ({pct:.1f}%)")
            print()

    # Comparison summary
    if len(all_stats) >= 2:
        print("=" * 80)
        print("COMPARISON SUMMARY")
        print("=" * 80)
        print()

        efficiencies = {}
        for filename, stats in all_stats.items():
            total_host_time = stats["total_samples"] * 3
            total_low_power_time = sum(
                stats["host_states"][host]["LOW_POWER"] for host in ["h1", "h2", "h3"]
            )
            efficiency = (
                (total_low_power_time / total_host_time * 100)
                if total_host_time > 0
                else 0
            )
            efficiencies[scenario_names.get(filename, filename)] = efficiency

        print("Energy Efficiency Comparison:")
        for name, eff in sorted(efficiencies.items(), key=lambda x: x[1], reverse=True):
            print(f"  {name}: {eff:.1f}% time in LOW_POWER")
        print()

        if "MTD with Power Management" in efficiencies and "No MTD" in efficiencies:
            improvement = (
                efficiencies["MTD with Power Management"] - efficiencies["No MTD"]
            )
            print(
                f"Energy Savings: {improvement:.1f}% improvement with power management"
            )
        print()


if __name__ == "__main__":
    import os

    # Default files
    default_files = [
        "scenario1_no_mtd.csv",
        "scenario2_mtd_no_power.csv",
        "scenario2_mtd_with_power.csv",
    ]

    if len(sys.argv) > 1:
        files = sys.argv[1:]
    else:
        files = [f for f in default_files if os.path.exists(f)]

    if not files:
        print("No scenario files found!")
        print("Usage: python3 analyze_scenarios.py [file1.csv] [file2.csv] ...")
        sys.exit(1)

    print_comparison(files)
