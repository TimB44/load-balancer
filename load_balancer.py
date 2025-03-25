from pox.core import core
import pox.openflow.libopenflow_01 as of
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


def swap_server():
    global next_server
    if next_server == ip_5_server:
        next_server = ip_6_server
    else:
        assert next_server == ip_6_server
        next_server = ip_5_server


def arp_handler(event):

    log.info(f"PRINTIN CONNECTIONS")
    for con in core.openflow.connections:
        log.info(f"CONN = {con}")
    packet = event.parsed
    if packet.type == packet.ARP_TYPE:
        arp = packet.find("arp")
        if arp is not None and arp.opcode == arp.REQUEST:
            log.info(
                f"ARP request: Who has {arp.protodst}? Tell {arp.protosrc}, src = {arp.src}, dest = {arp.dest}"
            )

            # if arp.src == virtual_ip:
            #     assert False, "TODO"
            # else:
            # arp_reply = of.ofp_packet_out()

            # Fill in your ARP resolution logic here
            # Example:
            # if arp.protodst == IPAddr("192.168.1.1"):
            #     arp_reply = of.ofp_packet_out()
            #     arp_reply.data = ...
            #     event.connection.send(arp_reply)


# Launch POX component
def launch():
    core.openflow.addListenerByName("PacketIn", arp_handler)
    log.info("ARP logger running...")
