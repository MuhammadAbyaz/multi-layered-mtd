## Multi-Layered MTD Setup

### How to Enable Multi-Layered MTD

Multi-layered MTD combines **Layer 1 (IP Hopping)** and **Layer 2 (Port Hopping)** for enhanced security.

#### Configuration Options

The MTD behavior is controlled by environment variables:

- **THREAT_LEVEL**: `LOW`, `MEDIUM`, or `HIGH`
- **ENERGY_MODE**: `LOW` or `NORMAL`
- **HOP_INTERVAL**: Interval in seconds (default: 5)
- **VIRTUAL_IP**: Virtual IP address (default: 10.0.0.100)
- **VIRTUAL_MAC**: Virtual MAC address (default: 02:00:00:aa:bb:cc)
- **POWER_MANAGEMENT**: `ON` or `OFF` (default: OFF) - Enables energy-efficient power management

#### MTD Decision Matrix

| Threat Level | Energy Mode | MTD Layer | Behavior |
|-------------|-------------|-----------|----------|
| HIGH | NORMAL | **L2 (Multi-Layer)** | Port Hopping + IP Hopping |
| HIGH | LOW | L1 | IP Hopping only |
| MEDIUM | NORMAL | L1 | IP Hopping only |
| MEDIUM | LOW | OFF | MTD Disabled |
| LOW | Any | OFF | MTD Disabled |

### Step-by-Step Instructions

#### 1. Start the Ryu Controller with Multi-Layered MTD

To enable **multi-layered MTD** (Layer 2), set `THREAT_LEVEL=HIGH` and `ENERGY_MODE=NORMAL`:

```bash
# Activate virtual environment (if using one)
source sdn-env/bin/activate

# Start Ryu controller with multi-layered MTD enabled
THREAT_LEVEL=HIGH ENERGY_MODE=NORMAL HOP_INTERVAL=5 \
    ryu-manager mtd_multi_layer.py --verbose
```

**Alternative configurations:**

```bash
# Single-layer MTD (IP hopping only)
THREAT_LEVEL=HIGH ENERGY_MODE=LOW ryu-manager mtd_multi_layer.py

# Medium threat with IP hopping
THREAT_LEVEL=MEDIUM ENERGY_MODE=NORMAL ryu-manager mtd_multi_layer.py

# MTD disabled
THREAT_LEVEL=LOW ryu-manager mtd_multi_layer.py
```

#### 2. Start Mininet

In a separate terminal:

```bash
sudo mn --controller=remote,ip=127.0.0.1,port=6633 \
        --topo=single,3 --switch=ovsk,protocols=OpenFlow13 --mac --arp
```

#### 3. Verify MTD is Running

Check the Ryu controller logs. You should see:
- `[DECISION] HIGH Threat + NORMAL Energy -> L2 (Port Hop)`
- `[L2 MTD] VIP Port -> <port> (Port Hop)`
- `[L1 MTD] VIP <virtual_ip>:<port> -> <real_ip> (IP Hop)`

### Testing Multi-Layered MTD

The virtual IP will hop between:
- **IP addresses** (Layer 1): Cycles through available host IPs
- **Ports** (Layer 2): Cycles through [80, 8080, 8000, 9000]

The server always listens on port **8080** (BASE_SERVER_PORT), but clients must connect to the current active VIP port.

## Energy-Efficient Power Management

The MTD system now supports power management to reduce energy consumption. When enabled, hosts that are NOT assigned the virtual IP are put into low-power mode (server suspended), and only the active host remains fully operational.

### Enabling Power Management

```bash
# Start controller with power management enabled
POWER_MANAGEMENT=ON THREAT_LEVEL=HIGH ENERGY_MODE=NORMAL \
    ryu-manager mtd_multi_layer.py --verbose
```

### How It Works

1. **Initialization**: All hosts start in LOW_POWER mode
2. **IP Hop**: When virtual IP hops to a new host:
   - Old host → LOW_POWER (server suspended)
   - New host → ACTIVE (server resumed)
3. **State Tracking**: Controller tracks power state for all hosts

### Host-Side Setup

The controller attempts to control hosts via SSH by default. For Mininet, it uses namespace commands.

**Quick Setup**:
- For Mininet: No additional setup needed (uses `ip netns exec`)
- For real networks: Set up SSH keys for passwordless access

### Monitoring

Check controller logs for power management events:
```
[POWER] Host 10.0.0.1 -> LOW_POWER (server suspended)
[POWER] Host 10.0.0.2 -> ACTIVE (server resumed)
```

## Energy Monitoring

To compare energy consumption across scenarios, use the monitor script from inside Mininet:

```bash
# In Mininet CLI:
h2 python3 /home/muhammad-abyaz/workspace/mininet/monitor_from_mininet.py 60 /tmp/scenario1_no_mtd.csv
```

The monitor automatically detects IP hopping and adjusts host states accordingly:
- **Scenario 1 (No MTD)**: Only virtual holder (h1) shows as ACTIVE
- **Scenario 2 (MTD no power)**: All hosts show as ACTIVE (all servers running)
- **Scenario 3 (MTD with power)**: Only current holder shows as ACTIVE (others LOW_POWER)

After monitoring, analyze results:
```bash
python3 analyze_scenarios.py scenario1_no_mtd.csv scenario2_mtd_no_power.csv scenario2_mtd_with_power.csv
```