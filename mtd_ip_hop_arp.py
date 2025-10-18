# mtd_ip_hop_full_l2.py - Corrected Version
import os, time, threading, logging
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp
from ryu.lib import mac

# --- Configuration ---
VIRTUAL_IP = os.environ.get("VIRTUAL_IP", "10.0.0.100")
VIRTUAL_MAC = os.environ.get("VIRTUAL_MAC", "02:00:00:aa:bb:cc")
try:
    HOP_INTERVAL = int(os.environ.get("HOP_INTERVAL", "5"))
except:
    HOP_INTERVAL = 10
# --- End Configuration ---


class MTDIpHopFullL2(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MTDIpHopFullL2, self).__init__(*args, **kwargs)
        # ip -> (dpid, port, mac)
        self.host_ip_map = {}
        # dpid -> datapath
        self.dp_map = {}
        # The IP of the current server holding the VIP
        self.virtual_holder = None
        self.lock = threading.Lock()

        self.hop_thread = threading.Thread(target=self._hop_loop)
        self.hop_thread.daemon = True
        self.hop_thread.start()

        self.logger.setLevel(logging.INFO)
        self.logger.info(
            "MTD IP Hop Full L2 started. VIP=%s VMAC=%s interval=%s",
            VIRTUAL_IP,
            VIRTUAL_MAC,
            HOP_INTERVAL,
        )

    # --- Utility Methods ---

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

    def _send_arp_reply(self, datapath, src_mac, src_ip, dst_mac, dst_ip, out_port):
        eth_pkt = ethernet.ethernet(dst=dst_mac, src=src_mac, ethertype=0x0806)
        arp_pkt = arp.arp(
            hwtype=1,
            proto=0x0800,
            hlen=6,
            plen=4,
            opcode=2,
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
            opcode=2,
            src_mac=src_mac,
            src_ip=src_ip,
            dst_mac="00:00:00:00:00:00",
            dst_ip=src_ip,
        )
        p = packet.Packet()
        p.add_protocol(eth_pkt)
        p.add_protocol(arp_pkt)
        p.serialize()
        # Flood GARP on all datapaths
        for dp in self.dp_map.values():
            self._send_packet_out(dp, p.data, dp.ofproto.OFPP_FLOOD)

    # --- Flow Installation Methods ---

    def _install_client_to_server_flow(self, dp, target_ip, target_port, target_mac):
        """Installs the forward (Client -> Server) flow (DNAT)."""
        parser = dp.ofproto_parser
        ofp = dp.ofproto

        # Match traffic destined for the VIP
        # client -> VIP: rewrite ipv4_dst -> target_ip, set eth_dst -> target_mac, set eth_src -> VIRTUAL_MAC, output target_port
        match_cli = parser.OFPMatch(eth_type=0x0800, ipv4_dst=VIRTUAL_IP)
        actions_cli = [
            parser.OFPActionSetField(ipv4_dst=target_ip),
            parser.OFPActionSetField(eth_dst=target_mac),
            parser.OFPActionSetField(eth_src=VIRTUAL_MAC),
            parser.OFPActionOutput(target_port),
        ]
        inst_cli = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions_cli)]

        dp.send_msg(
            parser.OFPFlowMod(
                datapath=dp,
                priority=350,
                match=match_cli,
                instructions=inst_cli,
                idle_timeout=60,  # Reduced timeout for MTD
            )
        )

    def _install_server_to_client_flow(
        self, dp, server_ip, client_ip, client_mac, client_port
    ):
        """Installs the reverse (Server -> Client) flow (SNAT and D-MAC rewrite)."""
        parser = dp.ofproto_parser
        ofp = dp.ofproto

        # Match traffic originating from the current server and destined for a specific client
        # host -> client: match ipv4_src=server_ip, ipv4_dst=client_ip -> set ipv4_src=VIRTUAL_IP, set eth_src=VIRTUAL_MAC, set eth_dst=client_mac, output client_port
        match_rev = parser.OFPMatch(
            eth_type=0x0800, ipv4_src=server_ip, ipv4_dst=client_ip
        )
        actions_rev = [
            parser.OFPActionSetField(ipv4_src=VIRTUAL_IP),
            parser.OFPActionSetField(eth_src=VIRTUAL_MAC),
            parser.OFPActionSetField(eth_dst=client_mac),  # <--- THE CRITICAL FIX
            parser.OFPActionOutput(client_port),
        ]
        inst_rev = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions_rev)]

        # Use a high priority to ensure this rule is hit before any default L2
        dp.send_msg(
            parser.OFPFlowMod(
                datapath=dp,
                priority=400,
                match=match_rev,
                instructions=inst_rev,
                idle_timeout=60,  # Reduced timeout for MTD
            )
        )

    # --- Packet Handler ---

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

        # --- L2 Learning (Crucial for all forwarding) ---
        # Learn hosts based on observed IP/MAC/Port
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
            # dpid, port, mac
            self.host_ip_map[src_ip] = (dp.id, in_port, src_mac)

        # --- ARP Handling ---
        if (
            arp_pkt
            and arp_pkt.opcode == arp.ARP_REQUEST
            and arp_pkt.dst_ip == VIRTUAL_IP
        ):
            if self.virtual_holder and self.virtual_holder in self.host_ip_map:
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
            else:
                # Flood if no active virtual holder is known
                out = parser.OFPPacketOut(
                    datapath=dp,
                    buffer_id=msg.buffer_id,
                    in_port=in_port,
                    actions=[parser.OFPActionOutput(ofp.OFPP_FLOOD)],
                    data=msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None,
                )
                dp.send_msg(out)
                return

        # --- IP Packet Handling ---
        if ip_pkt:

            # Case 1: Client -> VIP (Forward Path)
            if ip_pkt.dst == VIRTUAL_IP:
                if self.virtual_holder and self.virtual_holder in self.host_ip_map:
                    # Target info (server)
                    tgt_dpid, tgt_port, tgt_mac = self.host_ip_map[self.virtual_holder]

                    # Install forward flow on all switches (proactive)
                    for dp2 in self.dp_map.values():
                        try:
                            self._install_client_to_server_flow(
                                dp2, self.virtual_holder, tgt_port, tgt_mac
                            )
                        except Exception:
                            self.logger.exception(
                                "install forward flow failed on dp %s", dp2.id
                            )

                    # Forward the current packet using the new flow actions
                    actions_now = [
                        parser.OFPActionSetField(ipv4_dst=self.virtual_holder),
                        parser.OFPActionSetField(eth_dst=tgt_mac),
                        parser.OFPActionSetField(eth_src=VIRTUAL_MAC),
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

            # Case 2: Server -> Client (Reverse Path - First Packet)
            elif ip_pkt.src == self.virtual_holder:
                client_ip = ip_pkt.dst

                # We need to find the client's info to install the reverse flow
                if client_ip in self.host_ip_map:
                    client_dpid, client_port, client_mac = self.host_ip_map[client_ip]

                    self.logger.info(
                        "Reverse flow: %s -> %s. Installing flow on all DPs.",
                        ip_pkt.src,
                        client_ip,
                    )

                    # Install reverse flow on all switches (proactive)
                    for dp2 in self.dp_map.values():
                        try:
                            self._install_server_to_client_flow(
                                dp2, ip_pkt.src, client_ip, client_mac, client_port
                            )
                        except Exception:
                            self.logger.exception(
                                "install reverse flow failed on dp %s", dp2.id
                            )

                    # Forward the current packet using the new flow actions
                    actions_now = [
                        parser.OFPActionSetField(ipv4_src=VIRTUAL_IP),
                        parser.OFPActionSetField(eth_src=VIRTUAL_MAC),
                        parser.OFPActionSetField(eth_dst=client_mac),
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
                # If client is not in map, fall through to default L2 forwarding

        # --- Default L2 Forward ---
        # Fallback to simple L2 learning/forwarding for all other traffic
        out_port = ofp.OFPP_FLOOD
        for ip, info in self.host_ip_map.items():
            # Match destination MAC to a learned host's MAC
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

    # --- MTD Hop Loop ---

    def _hop_loop(self):
        """Periodically changes the IP address (server) holding the VIP."""
        while True:
            with self.lock:
                # 1. Select the next holder
                if not self.host_ip_map:
                    time.sleep(1)
                    continue

                # Get all learned IPs (h1, h2, h3, and the servers) and sort them
                ips = sorted(self.host_ip_map.keys())

                if self.virtual_holder not in ips:
                    new = ips[0] if ips else None
                else:
                    idx = ips.index(self.virtual_holder)
                    new = ips[(idx + 1) % len(ips)]

                if new and new != self.virtual_holder:
                    self.virtual_holder = new
                    self.logger.info(
                        "VIP %s -> %s (VMAC %s)",
                        VIRTUAL_IP,
                        self.virtual_holder,
                        VIRTUAL_MAC,
                    )

                    # 2. Update Network State
                    try:
                        dpid, port, macaddr = self.host_ip_map[self.virtual_holder]
                        dp = self.dp_map.get(dpid)

                        # Send Gratuitous ARP to update client ARP caches
                        if dp:
                            self._send_gratuitous_arp(dp, VIRTUAL_MAC, VIRTUAL_IP)

                        # Proactively install ONLY the forward flows (Client -> Server)
                        for dp2 in self.dp_map.values():
                            try:
                                self._install_client_to_server_flow(
                                    dp2, self.virtual_holder, port, macaddr
                                )
                            except Exception:
                                self.logger.exception(
                                    "install forward flow failed on dp %s", dp2.id
                                )
                    except Exception:
                        self.logger.exception("GARP/install flows failed")

            time.sleep(HOP_INTERVAL)
