import os, time, threading, logging
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp, tcp, icmp
from ryu.lib import mac

# --- Configuration ---
VIRTUAL_IP = os.environ.get("VIRTUAL_IP", "10.0.0.100")
VIRTUAL_MAC = os.environ.get("VIRTUAL_MAC", "02:00:00:aa:bb:cc")
try:
    # MTD Policy Configuration
    HOP_INTERVAL = int(os.environ.get("HOP_INTERVAL", "5"))  # Base interval in seconds
    THREAT_LEVEL = os.environ.get("THREAT_LEVEL", "LOW")  # LOW, MEDIUM, HIGH
    ENERGY_MODE = os.environ.get("ENERGY_MODE", "NORMAL")  # LOW, NORMAL
except:
    HOP_INTERVAL = 5
    THREAT_LEVEL = "LOW"
    ENERGY_MODE = "NORMAL"

# Define the set of possible ports for Layer 2 Port Hopping
BASE_SERVER_PORT = 8080
VIRTUAL_PORTS = [80, 8080, 8000, 9000]

# --- Controller Class ---


class MTDMultiLayer(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MTDMultiLayer, self).__init__(*args, **kwargs)
        self.host_ip_map = {}  # ip -> (dpid, port, mac)
        self.dp_map = {}  # dpid -> datapath
        self.virtual_holder = None
        self.virtual_port_idx = 0
        self.current_vip_port = VIRTUAL_PORTS[0]
        self.total_flow_messages = 0
        self.lock = threading.Lock()

        # MTD decision engine replaces the simple hop_loop
        self.decision_thread = threading.Thread(target=self._decision_loop)
        self.decision_thread.daemon = True
        self.decision_thread.start()

        # CRITICAL FIX: Initialize MTD holder robustly in a separate thread
        init_thread = threading.Thread(target=self._initialize_mtd_holder)
        init_thread.daemon = True
        init_thread.start()

        self.logger.setLevel(logging.INFO)
        self.logger.info(
            "MTD Multi-Layer started. VIP=%s:%s VMAC=%s, THREAT=%s, ENERGY=%s",
            VIRTUAL_IP,
            self.current_vip_port,
            VIRTUAL_MAC,
            THREAT_LEVEL,
            ENERGY_MODE,
        )

    def _track_flow_message(self, count, action_name):
        """Helper to add to the total flow message count and log the action."""
        with self.lock:
            self.total_flow_messages += count
            self.logger.info(
                f"[OVERHEAD] +{count} FlowMsgs for {action_name}. Total: {self.total_flow_messages}"
            )

    # --- Initialization and ARP Probing ---
    def _send_packet_out(self, datapath, data, out_port):
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofp.OFP_NO_BUFFER,
            in_port=ofp.OFPP_CONTROLLER,
            actions=[parser.OFPActionOutput(out_port)],
            data=data,
        )
        datapath.send_msg(out)

    def _send_arp_request(self, datapath, target_ip):
        """Sends an ARP request from the controller to force hosts to reply, triggering learning."""
        ofp = datapath.ofproto

        # Use a dummy source MAC/IP since the controller is sending this
        src_ip = "0.0.0.0"
        src_mac = "00:00:00:00:00:00"

        eth_pkt = ethernet.ethernet(
            dst="ff:ff:ff:ff:ff:ff", src=src_mac, ethertype=0x0806
        )
        arp_pkt = arp.arp(
            hwtype=1,
            proto=0x0800,
            hlen=6,
            plen=4,
            opcode=arp.ARP_REQUEST,
            src_mac=src_mac,
            src_ip=src_ip,
            dst_mac="00:00:00:00:00:00",
            dst_ip=target_ip,
        )
        p = packet.Packet()
        p.add_protocol(eth_pkt)
        p.add_protocol(arp_pkt)
        p.serialize()

        # Send on all ports of all switches to ensure discovery
        self._send_packet_out(datapath, p.data, ofp.OFPP_FLOOD)
        self.logger.debug(f"Probing network for {target_ip} with ARP request.")

    def _initialize_mtd_holder(self):
        """Probes the network to populate the host map, then sets the initial holder."""
        self.logger.info("Initializing MTD holder: Waiting for switch connection...")

        # 1. CRITICAL WAIT: Wait until at least one switch (datapath) connects
        max_dp_wait = 5
        for i in range(max_dp_wait):
            if self.dp_map:
                self.logger.info(
                    f"Switch (dpid={list(self.dp_map.keys())[0]}) connected after {i} seconds."
                )
                break
            time.sleep(1)

        if not self.dp_map:
            self.logger.error(
                "No switches connected. Cannot proceed with MTD initialization."
            )
            return

        self.logger.info("Probing network for hosts...")

        # 2. Proactively send ARP requests for common Mininet host IPs to force learning
        # Pick the first datapath to send the ARP flood from
        dp = self.dp_map[list(self.dp_map.keys())[0]]
        for i in range(1, 6):  # Probe for 10.0.0.1 up to 10.0.0.5
            self._send_arp_request(dp, f"10.0.0.{i}")

        # Give hosts time to reply and the controller time to process the ARP replies
        time.sleep(2)

        # 3. Wait for the map to populate after probing
        max_host_wait = 5
        for i in range(max_host_wait):
            if len(self.host_ip_map) >= 2:  # Need at least 2 hosts (client and server)
                self.logger.info(f"Host map populated after {i+2} seconds.")
                break
            time.sleep(1)

        # 4. Set the initial holder
        with self.lock:
            self._hop_ip()
            if self.virtual_holder:
                self.logger.info(f"MTD holder initialized to: {self.virtual_holder}")
            else:
                self.logger.error(
                    "Failed to initialize MTD holder. host_ip_map is empty or contains too few entries."
                )

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        self.dp_map[dp.id] = dp
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        # Install Table-Miss Flow (sends everything to controller)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=0, match=match, instructions=inst)
        dp.send_msg(mod)
        self.logger.info("Installed table-miss on dpid=%s", dp.id)

    # --- Utility Methods ---
    def _send_arp_reply(self, datapath, src_mac, src_ip, dst_mac, dst_ip, out_port):
        eth_pkt = ethernet.ethernet(dst=dst_mac, src=src_mac, ethertype=0x0806)
        arp_pkt = arp.arp(
            hwtype=1,
            proto=0x0800,
            hlen=6,
            plen=4,
            opcode=arp.ARP_REPLY,
            src_mac=src_mac,
            src_ip=src_ip,
            dst_mac=dst_mac,
            dst_ip=dst_ip,
        )
        p = packet.Packet()
        p.add_protocol(eth_pkt)
        p.add_protocol(arp_pkt)
        p.serialize()
        self._send_packet_out(datapath, p.data, out_port)

    def _send_gratuitous_arp(self, dp, src_mac, src_ip):
        eth_pkt = ethernet.ethernet(
            dst="ff:ff:ff:ff:ff:ff", src=src_mac, ethertype=0x0806
        )
        arp_pkt = arp.arp(
            hwtype=1,
            proto=0x0800,
            hlen=6,
            plen=4,
            opcode=arp.ARP_REPLY,
            src_mac=src_mac,
            src_ip=src_ip,
            dst_mac="00:00:00:00:00:00",
            dst_ip=src_ip,
        )
        p = packet.Packet()
        p.add_protocol(eth_pkt)
        p.add_protocol(arp_pkt)
        p.serialize()
        for dp in self.dp_map.values():
            self._send_packet_out(dp, p.data, dp.ofproto.OFPP_FLOOD)

    def _delete_old_flows(self, old_vip_port):
        """Deletes all flows matching the previously active VIP port (for L2 enforcement)."""
        parser = self.dp_map[list(self.dp_map.keys())[0]].ofproto_parser
        ofp = self.dp_map[list(self.dp_map.keys())[0]].ofproto

        # Match for the old VIP port in the forward path (TCP_DST)
        match_forward = parser.OFPMatch(
            eth_type=0x0800, ip_proto=6, ipv4_dst=VIRTUAL_IP, tcp_dst=old_vip_port
        )

        for dp in self.dp_map.values():
            # Delete forward flows matching the old port
            mod_forward = parser.OFPFlowMod(
                datapath=dp,
                command=ofp.OFPFC_DELETE,
                out_port=ofp.OFPP_ANY,
                out_group=ofp.OFPG_ANY,
                priority=350,  # Match the priority of the installed forward flow
                match=match_forward,
            )
            dp.send_msg(mod_forward)
            self.logger.info(
                f"[L2 DELETE] Deleted forward flows for old port {old_vip_port} on dpid={dp.id}"
            )

    # --- Flow Installation ---
    def _install_client_to_server_flow(
        self, dp, target_ip, target_port, target_mac, client_vip_port
    ):
        """Installs the forward (Client -> Server) flow (DNAT and Port rewrite)."""
        parser = dp.ofproto_parser
        ofp = dp.ofproto

        # Match traffic destined for the VIP AND the current client-requested VIP port
        match_cli = parser.OFPMatch(
            eth_type=0x0800, ip_proto=6, ipv4_dst=VIRTUAL_IP, tcp_dst=client_vip_port
        )

        actions_cli = [
            # L3/L2 Rewrite
            parser.OFPActionSetField(ipv4_dst=target_ip),
            parser.OFPActionSetField(eth_dst=target_mac),
            parser.OFPActionSetField(eth_src=VIRTUAL_MAC),
            # L4 Rewrite - Redirect to the BASE_SERVER_PORT (8080)
            parser.OFPActionSetField(tcp_dst=BASE_SERVER_PORT),
            parser.OFPActionOutput(target_port),
        ]
        inst_cli = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions_cli)]

        dp.send_msg(
            parser.OFPFlowMod(
                datapath=dp,
                priority=350,
                match=match_cli,
                instructions=inst_cli,
                idle_timeout=HOP_INTERVAL * 2,
            )
        )

    def _install_server_to_client_flow(
        self, dp, server_ip, client_ip, client_mac, client_port, client_dynamic_port
    ):
        """Installs the reverse (Server -> Client) flow (SNAT and Port rewrite)."""
        parser = dp.ofproto_parser
        ofp = dp.ofproto

        # Match traffic originating from the current server (BASE_SERVER_PORT)
        # and destined for the client's dynamic ephemeral port.
        match_rev = parser.OFPMatch(
            eth_type=0x0800,
            ip_proto=6,
            ipv4_src=server_ip,
            ipv4_dst=client_ip,
            tcp_src=BASE_SERVER_PORT,
            tcp_dst=client_dynamic_port,  # CRITICAL FIX: Match on client's ephemeral port
        )

        actions_rev = [
            # L3/L2 Rewrite
            parser.OFPActionSetField(ipv4_src=VIRTUAL_IP),
            parser.OFPActionSetField(eth_src=VIRTUAL_MAC),
            parser.OFPActionSetField(eth_dst=client_mac),
            # L4 Rewrite - Rewrite back to the original client requested VIP port (e.g., 80)
            parser.OFPActionSetField(
                tcp_src=self.current_vip_port
            ),  # CRITICAL FIX: Rewrite to current VIP port
            parser.OFPActionOutput(client_port),
        ]
        inst_rev = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions_rev)]

        dp.send_msg(
            parser.OFPFlowMod(
                datapath=dp,
                priority=400,
                match=match_rev,
                instructions=inst_rev,
                idle_timeout=HOP_INTERVAL * 2,
            )
        )

    # --- Packet In Handler ---
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        icmp_pkt = pkt.get_protocol(icmp.icmp)

        # --- L2 Learning ---
        if arp_pkt:
            src_ip = arp_pkt.src_ip
            src_mac = arp_pkt.src_mac
        elif ip_pkt:
            src_ip = ip_pkt.src
            src_mac = eth.src
        else:
            src_ip = None
            src_mac = eth.src

        if src_ip:
            self.host_ip_map[src_ip] = (dp.id, in_port, src_mac)

        # --- ARP Handling ---
        if (
            arp_pkt
            and arp_pkt.opcode == arp.ARP_REQUEST
            and arp_pkt.dst_ip == VIRTUAL_IP
        ):
            if self.virtual_holder:
                self.logger.info(
                    "Replying ARP for VIP %s with VMAC %s", VIRTUAL_IP, VIRTUAL_MAC
                )
                self._send_arp_reply(
                    dp,
                    VIRTUAL_MAC,
                    VIRTUAL_IP,
                    arp_pkt.src_mac,
                    arp_pkt.src_ip,
                    in_port,
                )
            return

        # --- IP Packet & MTD Forwarding ---
        if ip_pkt:

            # --- 1. ICMP (PING) FORWARDING ---
            if ip_pkt.dst == VIRTUAL_IP and icmp_pkt:
                if self.virtual_holder and self.virtual_holder in self.host_ip_map:

                    tgt_dpid, tgt_port, tgt_mac = self.host_ip_map[self.virtual_holder]

                    # Define the actions for forwarding: VIP -> RIP
                    actions_now = [
                        parser.OFPActionSetField(ipv4_dst=self.virtual_holder),
                        parser.OFPActionSetField(eth_dst=tgt_mac),
                        parser.OFPActionSetField(eth_src=VIRTUAL_MAC),
                        parser.OFPActionOutput(tgt_port),
                    ]

                    # Send the Packet Out
                    out = parser.OFPPacketOut(
                        datapath=dp,
                        buffer_id=msg.buffer_id,
                        in_port=in_port,
                        actions=actions_now,
                        data=msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None,
                    )
                    dp.send_msg(out)
                    self.logger.info(
                        "Forwarded ICMP ping from %s to RIP: %s",
                        ip_pkt.src,
                        self.virtual_holder,
                    )
                    return

            # --- 2. Client -> VIP (Forward TCP Path - First Packet) ---
            elif ip_pkt.dst == VIRTUAL_IP and tcp_pkt:
                if self.virtual_holder and self.virtual_holder in self.host_ip_map:

                    client_vip_port = (
                        tcp_pkt.dst_port
                    )  # This is the client's requested VIP port (e.g., 80)

                    # CRITICAL CHECK: Ensure the client is targeting the CURRENTLY active VIP port.
                    if client_vip_port != self.current_vip_port:
                        self.logger.warning(
                            "Client requested port %d is not the current MTD port %d. Dropping.",
                            client_vip_port,
                            self.current_vip_port,
                        )
                        return  # Drop the packet as the port is incorrect

                    tgt_dpid, tgt_port, tgt_mac = self.host_ip_map[self.virtual_holder]

                    self.logger.info(
                        "Forward flow: %s:%s -> %s:%s. Installing flow.",
                        ip_pkt.src,
                        client_vip_port,
                        VIRTUAL_IP,
                        client_vip_port,
                    )

                    # Install forward flow on all switches
                    for dp2 in self.dp_map.values():
                        try:
                            self._install_client_to_server_flow(
                                dp2,
                                self.virtual_holder,
                                tgt_port,
                                tgt_mac,
                                client_vip_port,
                            )
                        except Exception:
                            self.logger.exception(
                                "install forward flow failed on dp %s", dp2.id
                            )

                    # Forward the current packet
                    actions_now = [
                        parser.OFPActionSetField(ipv4_dst=self.virtual_holder),
                        parser.OFPActionSetField(eth_dst=tgt_mac),
                        parser.OFPActionSetField(eth_src=VIRTUAL_MAC),
                        parser.OFPActionSetField(
                            tcp_dst=BASE_SERVER_PORT
                        ),  # L4 Rewrite to 8080
                        parser.OFPActionOutput(tgt_port),
                    ]
                    out = parser.OFPPacketOut(
                        datapath=dp,
                        buffer_id=msg.buffer_id,
                        in_port=in_port,
                        actions=actions_now,
                        data=msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None,
                    )
                    dp.send_msg(out)
                    return

            # --- 3. Server -> Client (Reverse TCP Path - First Packet) ---
            elif ip_pkt.src == self.virtual_holder and tcp_pkt:

                client_ip = ip_pkt.dst
                # The server's reply is destined for the client's ephemeral source port.
                client_dynamic_port = tcp_pkt.dst_port

                if client_ip in self.host_ip_map:
                    client_dpid, client_port, client_mac = self.host_ip_map[client_ip]

                    self.logger.info(
                        "Reverse flow: %s -> %s. Installing flow.",
                        ip_pkt.src,
                        client_ip,
                    )

                    # Install reverse flow on all switches
                    for dp2 in self.dp_map.values():
                        try:
                            self._install_server_to_client_flow(
                                dp2,
                                ip_pkt.src,
                                client_ip,
                                client_mac,
                                client_port,
                                client_dynamic_port,  # Pass client's dynamic port for matching
                            )
                        except Exception:
                            self.logger.exception(
                                "install reverse flow failed on dp %s", dp2.id
                            )

                    # Forward the current packet (apply the same actions as the flow mod)
                    actions_now = [
                        parser.OFPActionSetField(ipv4_src=VIRTUAL_IP),
                        parser.OFPActionSetField(eth_src=VIRTUAL_MAC),
                        parser.OFPActionSetField(eth_dst=client_mac),
                        # CRITICAL FIX: Rewrite the server's source port (8080) back to the VIP port (e.g., 80)
                        parser.OFPActionSetField(tcp_src=self.current_vip_port),
                        parser.OFPActionOutput(client_port),
                    ]
                    out = parser.OFPPacketOut(
                        datapath=dp,
                        buffer_id=msg.buffer_id,
                        in_port=in_port,
                        actions=actions_now,
                        data=msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None,
                    )
                    dp.send_msg(out)
                    return

        # --- Default L2 Forward ---
        out_port = ofp.OFPP_FLOOD
        for ip, info in self.host_ip_map.items():
            if info[2] == eth.dst:
                out_port = info[1]
                break

        out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=[parser.OFPActionOutput(out_port)],
            data=msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None,
        )
        dp.send_msg(out)

    # --- MTD Multi-Layer Logic (Unchanged) ---

    def _hop_ip(self):
        """Layer 1 MTD: Changes the Real IP (RIP) holder (Low Cost)."""
        ips = sorted(
            [
                ip
                for ip in self.host_ip_map.keys()
                if ip != VIRTUAL_IP and ip.startswith("10.0.0.")
            ]
        )
        if not ips:
            if "10.0.0.1" in self.host_ip_map:
                self.virtual_holder = "10.0.0.1"
            return

        # Cycle through IPs
        if self.virtual_holder not in ips:
            new = ips[0]
        else:
            idx = ips.index(self.virtual_holder)
            new = ips[(idx + 1) % len(ips)]

        if new != self.virtual_holder:
            self.virtual_holder = new
            self.logger.info(
                f"[L1 MTD] VIP {VIRTUAL_IP}:{self.current_vip_port} -> {self.virtual_holder} (IP Hop)"
            )

            # Send GARP and install new forward flows
            if self.virtual_holder in self.host_ip_map:
                dpid, port, macaddr = self.host_ip_map[self.virtual_holder]
                self._send_gratuitous_arp(
                    self.dp_map.get(dpid), VIRTUAL_MAC, VIRTUAL_IP
                )
                for dp2 in self.dp_map.values():
                    try:
                        # Install a catch-all flow for the current VIP port using the new RIP
                        self._install_client_to_server_flow(
                            dp2,
                            self.virtual_holder,
                            port,
                            macaddr,
                            self.current_vip_port,
                        )
                    except Exception:
                        self.logger.exception(
                            "install forward flow failed on dp %s during IP hop", dp2.id
                        )

    def _hop_port(self):
        """Layer 2 MTD: Changes the Virtual Port (Medium Cost)."""

        old_port = self.current_vip_port  # Store the old port for deletion

        self.virtual_port_idx = (self.virtual_port_idx + 1) % len(VIRTUAL_PORTS)
        new_port = VIRTUAL_PORTS[self.virtual_port_idx]

        if new_port != self.current_vip_port:
            self.current_vip_port = new_port
            self.logger.info(f"[L2 MTD] VIP Port -> {self.current_vip_port} (Port Hop)")

            # L1 MTD is required to install the new flow for the new port
            self._hop_ip()

            # CRITICAL FIX: PROACTIVE FLOW DELETION
            self._delete_old_flows(old_port)

    def _decision_loop(self):
        """MTD Trade-off Engine: Decides which MTD layer to run based on policy."""
        while True:
            time.sleep(HOP_INTERVAL)

            with self.lock:
                if not self.host_ip_map or len(self.host_ip_map) < 2:
                    continue

                # --- Decision Policy Implementation (Unchanged) ---
                mtd_layer = 0
                if THREAT_LEVEL == "HIGH":
                    if ENERGY_MODE == "NORMAL":
                        mtd_layer = 2
                        self.logger.info(
                            "[DECISION] HIGH Threat + NORMAL Energy -> L2 (Port Hop)"
                        )
                    else:  # ENERGY_MODE == "LOW"
                        mtd_layer = 1
                        self.logger.info(
                            "[DECISION] HIGH Threat + LOW Energy -> L1 (IP Hop) [Trade-off]"
                        )

                elif THREAT_LEVEL == "MEDIUM":
                    if ENERGY_MODE == "LOW":
                        mtd_layer = 0
                        self.logger.info(
                            "[DECISION] MEDIUM Threat + LOW Energy -> MTD OFF"
                        )
                    else:
                        mtd_layer = 1
                        self.logger.info(
                            "[DECISION] MEDIUM Threat + NORMAL Energy -> L1 (IP Hop)"
                        )

                # --- Execute MTD Layer ---
                if mtd_layer == 1:
                    self._hop_ip()
                    self.logger.info("[DECISION] MTD is currently ENABLED (Layer 1)")
                elif mtd_layer == 2:
                    self._hop_port()
                    self.logger.info("[DECISION] MTD is currently ENABLED (Layer 2)")
                else:
                    # MTD OFF (Layer 0) - only ensure holder is set for ARP
                    if not self.virtual_holder:
                        self._hop_ip()
                    self.logger.info("[DECISION] MTD is currently DISABLED (Layer 0)")
