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
                ip_addr = next_server
                swap_server()
                # TODO: add flows
            else:
                eth_addr = ip_to_mac[arp_request.protodst]
                ip_addr = arp_request.protodst

            arp_reply = arp()
            arp_reply.hwsrc = eth_addr
            arp_reply.hwdst = packet.src
            arp_reply.opcode = arp_request.REPLY
            arp_reply.protosrc = ip_addr
            arp_reply.protodst = packet.payload.protosrc
            ether = ethernet()
            ether.type = ethernet.ARP_TYPE
            ether.dst = packet.src
            ether.src = eth_addr
            ether.payload = arp_reply
            msg = of.ofp_packet_out()
            msg.data = ether.pack()
            msg.in_port = event.inport
            event.connection.send(msg)


# Launch POX component
def launch():
    core.openflow.addListenerByName("PacketIn", arp_handler)
    log.info("ARP logger running...")
