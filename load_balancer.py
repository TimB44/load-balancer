from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp, ethernet
from pox.lib.addresses import IPAddr, EthAddr

log = core.getLogger()

last_node_used = 5
virtual_ip = IPAddr("10.0.0.10")
ip_5_server = IPAddr("10.0.0.5")
ip_6_server = IPAddr("10.0.0.6")
next_server = ip_5_server
ip_to_mac = {
    IPAddr("10.0.0.1"): EthAddr("00:00:00:00:00:01"),
    IPAddr("10.0.0.2"): EthAddr("00:00:00:00:00:02"),
    IPAddr("10.0.0.3"): EthAddr("00:00:00:00:00:03"),
    IPAddr("10.0.0.4"): EthAddr("00:00:00:00:00:04"),
    IPAddr("10.0.0.5"): EthAddr("00:00:00:00:00:05"),
    IPAddr("10.0.0.6"): EthAddr("00:00:00:00:00:06"),
}

ip_to_port = {
    IPAddr("10.0.0.1"): 1,
    IPAddr("10.0.0.2"): 2,
    IPAddr("10.0.0.3"): 3,
    IPAddr("10.0.0.4"): 4,
    IPAddr("10.0.0.5"): 5,
    IPAddr("10.0.0.6"): 6,
}


def swap_server():
    global next_server
    if next_server == ip_5_server:
        next_server = ip_6_server
    else:
        assert next_server == ip_6_server
        next_server = ip_5_server


def arp_handler(event):
    log.info(f"PRINTIN CONNECTIONS")
    packet = event.parsed
    if packet.type == packet.ARP_TYPE:
        arp_request = packet.find("arp")
        if arp_request is not None and arp_request.opcode == arp_request.REQUEST:
            log.info(
                f"ARP request: Who has {arp_request.protodst}? Tell {arp_request.protosrc}, src = {arp_request.src}, dest = {arp_request.dest}"
            )

            if arp_request.protodst == virtual_ip:
                eth_addr = ip_to_mac[next_server]
                dest_ip_addr = next_server
                map_request_flow = of.ofp_flow_mod()
                # msg.data = event.ofp
                map_request_flow.match.dl_type = 0x0800
                map_request_flow.match.nw_dst = virtual_ip
                map_request_flow.match.nw_src = packet.src
                map_request_flow.actions.append(
                    of.ofp_action_output(port=ip_to_port[next_server])
                )
                map_request_flow.actions.append(
                    of.ofp_action_nw_addr.set_dst(dest_ip_addr)
                )
                event.connection.send(map_request_flow)

                map_response_flow = of.ofp_flow_mod()
                # msg.data = event.ofp
                map_response_flow.match.dl_type = 0x0800
                map_response_flow.match.nw_dst = packet.src
                map_response_flow.match.nw_src = next_server
                map_response_flow.actions.append(
                    of.ofp_action_output(port=ip_to_port[packet.src])
                )
                map_response_flow.actions.append(
                    of.ofp_action_nw_addr.set_src(virtual_ip)
                )
                event.connection.send(map_response_flow)

                swap_server()
            else:
                eth_addr = ip_to_mac[arp_request.protodst]
                dest_ip_addr = arp_request.protodst

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
            map_response.actions.append(of.ofp_action_output(port =
                                                      of.OFPP_IN_PORT))
            event.connection.send(map_response)



# Launch POX component
def launch():
    core.openflow.addListenerByName("PacketIn", arp_handler)
    log.info("ARP logger running...")

