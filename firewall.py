from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

def _handle_PacketIn(event):
    packet = event.parsed

    if not packet.parsed:
        return

    ip_packet = packet.find('ipv4')

    # Flood non-IP traffic
    if not ip_packet:
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        event.connection.send(msg)
        return

    src = str(ip_packet.srcip)
    dst = str(ip_packet.dstip)

    #  MULTIPLE BLOCK RULES
    if (src == "10.0.0.1" and dst == "10.0.0.2") or \
       (src == "10.0.0.3" and dst == "10.0.0.1"):

        log.info("Blocked %s -> %s", src, dst)

        # Install DROP flow with HIGH priority
        msg = of.ofp_flow_mod()
        msg.priority = 100
        msg.match.dl_type = 0x800
        msg.match.nw_src = ip_packet.srcip
        msg.match.nw_dst = ip_packet.dstip
        msg.actions = []  # Drop
        event.connection.send(msg)
        return

    #  ALLOW RULE
    msg = of.ofp_flow_mod()
    msg.priority = 10
    msg.match = of.ofp_match.from_packet(packet)
    msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
    event.connection.send(msg)

    # Send current packet
    msg = of.ofp_packet_out()
    msg.data = event.ofp
    msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
    event.connection.send(msg)


def launch():
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
    log.info("SDN Firewall running")
