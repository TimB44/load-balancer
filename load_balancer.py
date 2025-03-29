# PA2 - Load Balancer
#
# Author: Tim Blamires
# Date: 3/29/25
#
# A simple round-robin load balancing POX component
# Handles ARP requests and responds with the correct MAC address
# If the request is for the virtual IP, installs OpenFlow rules to forward traffic
# Dynamically redirects traffic between two backend servers (10.0.0.5 and 10.0.0.6)
# Ensures consistent client-server communication by rewriting IP addresses in packets

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp, ethernet
from pox.lib.addresses import IPAddr, EthAddr

log = core.getLogger()

# Virtual IP and backend servers for load balancing
virtual_ip = IPAddr("10.0.0.10")
ip_5_server = IPAddr("10.0.0.5")
ip_6_server = IPAddr("10.0.0.6")
next_server = ip_5_server

# Mapping of IPs to MAC addresses
ip_to_mac = {
    IPAddr("10.0.0.1"): EthAddr("00:00:00:00:00:01"),
    IPAddr("10.0.0.2"): EthAddr("00:00:00:00:00:02"),
    IPAddr("10.0.0.3"): EthAddr("00:00:00:00:00:03"),
    IPAddr("10.0.0.4"): EthAddr("00:00:00:00:00:04"),
    IPAddr("10.0.0.5"): EthAddr("00:00:00:00:00:05"),
    IPAddr("10.0.0.6"): EthAddr("00:00:00:00:00:06"),
}

# Mapping of IPs to switch ports
ip_to_port = {
    IPAddr("10.0.0.1"): 1,
    IPAddr("10.0.0.2"): 2,
    IPAddr("10.0.0.3"): 3,
    IPAddr("10.0.0.4"): 4,
    IPAddr("10.0.0.5"): 5,
    IPAddr("10.0.0.6"): 6,
}


# Alternates the next_server between ip_5_server and ip_6_server for load balancing
def swap_server():
    global next_server
    if next_server == ip_5_server:
        next_server = ip_6_server
    else:
        assert next_server == ip_6_server
        next_server = ip_5_server


# Processes incoming ARP requests and responds with the correct MAC address
# If the request is for the virtual IP, sets up flow rules to forward traffic
# Implements round-robin load balancing between the two hosts
def arp_handler(event):
    packet = event.parsed
    # Only handle ARP packets
    if packet.type != packet.ARP_TYPE:
        return
    arp_request = packet.find("arp")

    # Only handle ARP requests
    if arp_request is None and arp_request.opcode != arp_request.REQUEST:
        return

    arp_src_ip = arp_request.protosrc
    arp_dest_ip = arp_request.protodst
    log.info(f"ARP request: NEED {arp_dest_ip} FROM {arp_src_ip}")
    # If the request is to the virtual IP then add flows to facilitate the ping
    if arp_dest_ip == virtual_ip:
        dest_ip_addr = next_server
        eth_addr = ip_to_mac[dest_ip_addr]
        swap_server()

        # Add flow for the ping request
        map_request_flow = of.ofp_flow_mod()
        map_request_flow.match.dl_type = 0x0800
        map_request_flow.match.nw_dst = virtual_ip
        map_request_flow.match.nw_src = arp_src_ip
        map_request_flow.actions.append(of.ofp_action_nw_addr.set_dst(dest_ip_addr))
        map_request_flow.actions.append(
            of.ofp_action_output(port=ip_to_port[dest_ip_addr])
        )
        event.connection.send(map_request_flow)

        # Add flow for the ping response this will remap the source IP address
        # to be the
        map_response_flow = of.ofp_flow_mod()
        map_response_flow.match.dl_type = 0x0800
        map_response_flow.match.nw_dst = arp_src_ip
        map_response_flow.match.nw_src = dest_ip_addr
        map_response_flow.actions.append(of.ofp_action_nw_addr.set_src(virtual_ip))
        map_response_flow.actions.append(
            of.ofp_action_output(port=ip_to_port[arp_src_ip])
        )
        event.connection.send(map_response_flow)

    else:
        # If the IP is not virtual then just resolve it to the correct MAC Address
        eth_addr = ip_to_mac[arp_request.protodst]
        dest_ip_addr = arp_request.protodst

    # Respond to the ARP with the MAC address in the eth_addr variable.
    arp_reply = arp()
    arp_reply.hwsrc = eth_addr
    arp_reply.hwdst = packet.src
    arp_reply.opcode = arp.REPLY
    arp_reply.protosrc = arp_request.protodst
    arp_reply.protodst = packet.payload.protosrc
    ether = ethernet()
    ether.type = ethernet.ARP_TYPE
    ether.dst = packet.src
    ether.src = eth_addr
    ether.payload = arp_reply
    map_response = of.ofp_packet_out()
    map_response.data = ether.pack()
    map_response.in_port = event.port
    map_response.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))
    event.connection.send(map_response)


# Launch POX component
def launch():
    # Listen for the PacketIn Event in order to respond to ARP requests
    core.openflow.addListenerByName("PacketIn", arp_handler)
    log.info("ARP Responder running...")
