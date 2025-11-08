# Running Energy Comparison Scenarios

## Prerequisites

1. Start Mininet:
```bash
sudo mn --controller=remote,ip=127.0.0.1,port=6633 --topo=single,3 --switch=ovsk,protocols=OpenFlow13 --mac --arp
```

2. In Mininet CLI, start all servers:
```bash
h1 python3 -m http.server 8080 --bind 0.0.0.0 > /tmp/h1_server.log 2>&1 &
h2 python3 -m http.server 8080 --bind 0.0.0.0 > /tmp/h2_server.log 2>&1 &
h3 python3 -m http.server 8080 --bind 0.0.0.0 > /tmp/h3_server.log 2>&1 &
```

## Scenario 1: No MTD

**Controller:**
```bash
THREAT_LEVEL=LOW ryu-manager mtd_multi_layer.py --verbose
```

**Monitor (in Mininet CLI):**
```bash
h2 python3 /home/muhammad-abyaz/workspace/mininet/monitor_from_mininet.py 60 /tmp/scenario1_no_mtd.csv
```

**Expected:** Only h1 ACTIVE (virtual holder), h2/h3 LOW_POWER

## Scenario 2: MTD without Power Management

**Controller:**
```bash
THREAT_LEVEL=HIGH ENERGY_MODE=NORMAL POWER_MANAGEMENT=OFF ryu-manager mtd_multi_layer.py --verbose
```

**Monitor (in Mininet CLI):**
```bash
h2 python3 /home/muhammad-abyaz/workspace/mininet/monitor_from_mininet.py 60 /tmp/scenario2_mtd_no_power.csv
```

**Expected:** IP/Port hopping, ALL hosts ACTIVE (all servers running)

## Scenario 3: MTD with Power Management

**Controller:**
```bash
THREAT_LEVEL=HIGH ENERGY_MODE=NORMAL POWER_MANAGEMENT=ON ryu-manager mtd_multi_layer.py --verbose
```

**Monitor (in Mininet CLI):**
```bash
h2 python3 /home/muhammad-abyaz/workspace/mininet/monitor_from_mininet.py 60 /tmp/scenario2_mtd_power.csv
```

**Expected:** IP/Port hopping, only current holder ACTIVE, others LOW_POWER

## Analyze Results

```bash
python3 analyze_scenarios.py scenario1_no_mtd.csv scenario2_mtd_no_power.csv scenario2_mtd_power.csv
```

