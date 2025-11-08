#!/usr/bin/env python3
"""
Generate energy usage graphs for MTD scenarios
"""

import csv
import matplotlib.pyplot as plt
import sys
import os

# Energy consumption per host (normalized)
ACTIVE_POWER = 1.0  # Full power consumption
LOW_POWER_POWER = 0.1  # 10% power consumption in low power mode


def load_scenario_data(filename):
    """Load scenario data from CSV file."""
    if not os.path.exists(filename):
        return None

    timestamps = []
    energy_consumption = []  # Total energy at each timestamp
    active_hosts_count = []  # Number of active hosts at each timestamp

    with open(filename, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Parse timestamp
            try:
                ts = float(row["timestamp"])
                timestamps.append(ts)
            except (ValueError, KeyError):
                continue

            # Calculate energy consumption
            # Count ACTIVE hosts
            active_count = 0
            for host in ["h1_state", "h2_state", "h3_state"]:
                state = row.get(host, "UNKNOWN")
                if state == "ACTIVE":
                    active_count += 1

            active_hosts_count.append(active_count)

            # Calculate total energy: ACTIVE hosts consume full power, LOW_POWER hosts consume 10%
            low_power_count = 3 - active_count
            total_energy = (active_count * ACTIVE_POWER) + (
                low_power_count * LOW_POWER_POWER
            )
            energy_consumption.append(total_energy)

    return {
        "timestamps": timestamps,
        "energy": energy_consumption,
        "active_hosts": active_hosts_count,
    }


def plot_energy_comparison(scenario_files, output_file="energy_usage_comparison.png"):
    """Generate energy usage comparison graph."""

    scenario_names = {
        "scenario1_no_mtd.csv": "No MTD",
        "scenario2_mtd_no_power.csv": "MTD without Power Management",
        "scenario3_mtd_power.csv": "MTD with Power Management",
    }

    # Colors for each scenario
    colors = {
        "No MTD": "#2E86AB",  # Blue
        "MTD without Power Management": "#A23B72",  # Purple
        "MTD with Power Management": "#F18F01",  # Orange
    }

    fig = plt.figure(figsize=(16, 14))
    gs = fig.add_gridspec(
        4, 2, hspace=0.35, wspace=0.3, height_ratios=[2, 2, 2, 1], width_ratios=[1, 1]
    )

    ax1 = fig.add_subplot(gs[0, :])  # Energy consumption over time (full width)
    ax2 = fig.add_subplot(gs[1, :])  # Active hosts over time (full width)
    ax3 = fig.add_subplot(gs[2, 0])  # Cumulative energy over time
    ax4 = fig.add_subplot(gs[2, 1])  # Energy distribution histogram
    ax5 = fig.add_subplot(gs[3, :])  # Average energy comparison bar chart (full width)

    fig.suptitle(
        "Energy Consumption Comparison Across MTD Scenarios",
        fontsize=16,
        fontweight="bold",
    )

    all_data = {}

    for filename in scenario_files:
        if not os.path.exists(filename):
            print(f"⚠️  Warning: {filename} not found, skipping...")
            continue

        name = scenario_names.get(filename, filename)
        data = load_scenario_data(filename)

        if not data or len(data["timestamps"]) == 0:
            print(f"⚠️  Warning: {filename} has no data, skipping...")
            continue

        all_data[name] = data

        # Normalize timestamps to start from 0
        start_time = data["timestamps"][0]
        normalized_times = [(t - start_time) for t in data["timestamps"]]

        # Plot 1: Energy consumption over time
        ax1.plot(
            normalized_times,
            data["energy"],
            label=name,
            color=colors.get(name, "black"),
            linewidth=2,
            alpha=0.8,
        )

        # Plot 2: Number of active hosts over time
        ax2.plot(
            normalized_times,
            data["active_hosts"],
            label=name,
            color=colors.get(name, "black"),
            linewidth=2,
            alpha=0.8,
            marker="o",
            markersize=4,
        )

        # Plot 3: Cumulative energy consumption over time
        cumulative_energy = []
        cumsum = 0
        for energy in data["energy"]:
            cumsum += energy
            cumulative_energy.append(cumsum)

        ax3.plot(
            normalized_times,
            cumulative_energy,
            label=name,
            color=colors.get(name, "black"),
            linewidth=2.5,
            alpha=0.8,
        )

        # Plot 4: Energy distribution histogram
        ax4.hist(
            data["energy"],
            bins=20,
            alpha=0.6,
            label=name,
            color=colors.get(name, "black"),
            edgecolor="black",
        )

    # Configure Plot 1: Energy Consumption
    ax1.set_xlabel("Time (seconds)", fontsize=12)
    ax1.set_ylabel("Total Energy Consumption\n(Normalized Units)", fontsize=12)
    ax1.set_title("Energy Consumption Over Time", fontsize=14, fontweight="bold")
    ax1.legend(loc="best", fontsize=10)
    ax1.grid(True, alpha=0.3)
    ax1.set_ylim(0, 3.5)

    # Add horizontal lines for reference
    ax1.axhline(y=1.2, color="gray", linestyle="--", alpha=0.5, label="1 host ACTIVE")
    ax1.axhline(y=2.4, color="gray", linestyle="--", alpha=0.5, label="2 hosts ACTIVE")
    ax1.axhline(y=3.0, color="gray", linestyle="--", alpha=0.5, label="3 hosts ACTIVE")

    # Configure Plot 2: Active Hosts Count
    ax2.set_xlabel("Time (seconds)", fontsize=12)
    ax2.set_ylabel("Number of ACTIVE Hosts", fontsize=12)
    ax2.set_title("Active Hosts Over Time", fontsize=14, fontweight="bold")
    ax2.legend(loc="best", fontsize=10)
    ax2.grid(True, alpha=0.3)
    ax2.set_ylim(-0.2, 3.5)
    ax2.set_yticks([0, 1, 2, 3])

    # Configure Plot 3: Cumulative Energy
    ax3.set_xlabel("Time (seconds)", fontsize=11)
    ax3.set_ylabel("Cumulative Energy\n(units)", fontsize=11)
    ax3.set_title(
        "Cumulative Energy Consumption Over Time", fontsize=12, fontweight="bold"
    )
    ax3.legend(loc="best", fontsize=9)
    ax3.grid(True, alpha=0.3)

    # Configure Plot 4: Energy Distribution
    ax4.set_xlabel("Energy Consumption (units)", fontsize=11)
    ax4.set_ylabel("Frequency", fontsize=11)
    ax4.set_title("Energy Consumption Distribution", fontsize=12, fontweight="bold")
    ax4.legend(loc="best", fontsize=9)
    ax4.grid(True, alpha=0.3, axis="y")

    # Plot 5: Average Energy Comparison Bar Chart
    if len(all_data) > 0:
        scenario_names_list = []
        avg_energies = []
        bar_colors = []

        for name, data in all_data.items():
            if len(data["energy"]) > 0:
                avg_energy = sum(data["energy"]) / len(data["energy"])
                scenario_names_list.append(name)
                avg_energies.append(avg_energy)
                bar_colors.append(colors.get(name, "gray"))

        if scenario_names_list:
            bars = ax5.bar(
                scenario_names_list,
                avg_energies,
                color=bar_colors,
                alpha=0.7,
                edgecolor="black",
                linewidth=1.5,
            )
            ax5.set_ylabel("Average Energy\nConsumption (units)", fontsize=11)
            ax5.set_title(
                "Average Energy Consumption Comparison", fontsize=12, fontweight="bold"
            )
            ax5.grid(True, alpha=0.3, axis="y")
            ax5.set_ylim(0, max(avg_energies) * 1.2 if avg_energies else 3.5)

            # Add value labels on bars
            for bar, energy in zip(bars, avg_energies):
                height = bar.get_height()
                ax5.text(
                    bar.get_x() + bar.get_width() / 2.0,
                    height,
                    f"{energy:.2f}",
                    ha="center",
                    va="bottom",
                    fontsize=10,
                    fontweight="bold",
                )

            # Rotate x-axis labels if needed
            ax5.tick_params(axis="x", rotation=15, labelsize=9)

    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches="tight")
    print(f"✓ Graph saved to: {output_file}")

    # Calculate and print statistics
    print("\n" + "=" * 80)
    print("ENERGY CONSUMPTION STATISTICS")
    print("=" * 80)

    for name, data in all_data.items():
        if len(data["energy"]) > 0:
            avg_energy = sum(data["energy"]) / len(data["energy"])
            avg_active = sum(data["active_hosts"]) / len(data["active_hosts"])
            total_energy = sum(data["energy"])

            print(f"\n{name}:")
            print(f"  Average Energy Consumption: {avg_energy:.2f} units")
            print(f"  Average Active Hosts: {avg_active:.2f}")
            print(f"  Total Energy Consumption: {total_energy:.2f} units")
            print(
                f"  Energy Efficiency: {(1 - avg_energy/3.0)*100:.1f}% savings vs all ACTIVE"
            )

    # Detailed Comparison and Analysis
    if len(all_data) >= 2:
        print("\n" + "=" * 80)
        print("DETAILED ENERGY ANALYSIS")
        print("=" * 80)

        efficiencies = {}
        energy_details = {}

        for name, data in all_data.items():
            if len(data["energy"]) > 0:
                avg_energy = sum(data["energy"]) / len(data["energy"])
                efficiencies[name] = avg_energy

                # Calculate percentage of time each host is ACTIVE
                total_samples = len(data["active_hosts"])
                if total_samples > 0:
                    # For now, use active_hosts count as proxy
                    energy_details[name] = {
                        "avg_energy": avg_energy,
                        "avg_active_hosts": sum(data["active_hosts"]) / total_samples,
                        "min_energy": min(data["energy"]),
                        "max_energy": max(data["energy"]),
                        "total_samples": total_samples,
                    }

        sorted_eff = sorted(efficiencies.items(), key=lambda x: x[1])
        print("\n📊 Energy Consumption Ranking (lowest = most efficient):")
        for rank, (name, avg_energy) in enumerate(sorted_eff, 1):
            print(f"  {rank}. {name}: {avg_energy:.2f} units")
            if name in energy_details:
                details = energy_details[name]
                print(
                    f"     - Range: {details['min_energy']:.2f} - {details['max_energy']:.2f} units"
                )
                print(f"     - Avg Active Hosts: {details['avg_active_hosts']:.2f}")

        # Calculate savings percentages
        print("\n💡 Energy Savings Analysis:")
        if "No MTD" in efficiencies:
            baseline = efficiencies["No MTD"]
            print(f"  Baseline (No MTD): {baseline:.2f} units")

            if "MTD without Power Management" in efficiencies:
                mtd_no_power = efficiencies["MTD without Power Management"]
                increase = ((mtd_no_power - baseline) / baseline) * 100
                print(
                    f"  MTD without Power Management: {mtd_no_power:.2f} units ({increase:+.1f}% vs baseline)"
                )

            if "MTD with Power Management" in efficiencies:
                mtd_power = efficiencies["MTD with Power Management"]
                savings = ((baseline - mtd_power) / baseline) * 100
                print(
                    f"  MTD with Power Management: {mtd_power:.2f} units ({savings:+.1f}% vs baseline)"
                )

                if "MTD without Power Management" in efficiencies:
                    mtd_no_power = efficiencies["MTD without Power Management"]
                    savings_vs_no_power = (
                        (mtd_no_power - mtd_power) / mtd_no_power
                    ) * 100
                    print(f"\n  🎯 Power Management Benefit:")
                    print(
                        f"     {savings_vs_no_power:.1f}% energy reduction when power management is enabled"
                    )

        print("\n" + "=" * 80)
        print("CONCLUSION")
        print("=" * 80)
        best = sorted_eff[0]
        worst = sorted_eff[-1]
        print(f"✅ Most Energy Efficient: {best[0]} ({best[1]:.2f} units)")
        print(f"❌ Least Energy Efficient: {worst[0]} ({worst[1]:.2f} units)")

        if len(sorted_eff) >= 2:
            improvement = ((worst[1] - best[1]) / worst[1]) * 100
            print(
                f"📈 Potential Energy Savings: {improvement:.1f}% by using the most efficient scenario"
            )


if __name__ == "__main__":
    # Default files
    default_files = [
        "scenario1_no_mtd.csv",
        "scenario2_mtd_no_power.csv",
        "scenario3_mtd_power.csv",
    ]

    if len(sys.argv) > 1:
        files = sys.argv[1:]
    else:
        files = [f for f in default_files if os.path.exists(f)]

    if not files:
        print("No scenario files found!")
        print("Usage: python3 plot_energy_usage.py [file1.csv] [file2.csv] ...")
        sys.exit(1)

    output_file = "energy_usage_comparison.png"
    if len(sys.argv) > 1 and sys.argv[-1].endswith(".png"):
        output_file = sys.argv[-1]
        files = files[:-1]

    plot_energy_comparison(files, output_file)
