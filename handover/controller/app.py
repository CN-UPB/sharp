import logging

from ryu.app.wsgi import WSGIApplication
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import dpid as dpid_lib
from ryu.lib.packet.ethernet import ethernet
from ryu.ofproto import ofproto_v1_3
from ryu.topology.event import EventSwitchEnter, EventSwitchLeave, EventHostAdd, EventPortDelete

from handover.controller.constants import CONTROL_MESSAGE_ETHER_TYPE
from handover.controller.controller import HandoverController
from handover.controller.handover_message_wrapper import HandoverMessageWrapper

SWITCHID_PATTERN = dpid_lib.DPID_PATTERN + r'|all'


class HandoverApi(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(HandoverApi, self).__init__(*args, **kwargs)
        self.logger.addHandler(logging.handlers.WatchedFileHandler('/ctrl.log'))
        HandoverController.set_logger(self.logger)

        wsgi = kwargs['wsgi']
        self.waiters = {}
        self.data = {}
        wsgi.registory['HandoverController'] = self.data
        wsgi.register(HandoverController, self.data)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_feature_handler(self, ev):
        """
        Handler for switches that come online. Used for registering default flow mods.
        :param ev: 
        :return: 
        """
        HandoverController.switch_features_handler(ev.msg.datapath)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        OpenFlow PacketIn event handler. Passes event message to the controller.
        :param ev: 
        :return: 
        """
        msg = ev.msg
        HandoverController.packet_in_handler(msg)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        """
        OpenFlow FlowRemoved event handler. Passes event message to the controller.
        :param ev: 
        :return: 
        """
        HandoverController.flow_removed_handler(ev.msg)

    @set_ev_cls(EventSwitchEnter, MAIN_DISPATCHER)
    def switch_enter_handler(self, ev):
        """
        Handler for switch joining the network. Passes switch to the controller.
        :param ev: 
        :return: 
        """
        HandoverController.add_switch(ev.switch)

    @set_ev_cls(EventSwitchLeave, MAIN_DISPATCHER)
    def switch_leave_handler(self, ev):
        """
        Handler for switch leaving the network. Passes switch to the controller.
        :param ev: 
        :return: 
        """
        HandoverController.remove_switch(ev.switch)

    @set_ev_cls(EventHostAdd, MAIN_DISPATCHER)
    def host_add_handler(self, ev):
        """
        Handler for host joining the network. Passes host port to the controller.
        :param ev: 
        :return: 
        """
        HandoverController.host_add_handler(ev.host)

    @set_ev_cls(EventPortDelete, MAIN_DISPATCHER)
    def port_delete_handler(self, ev):
        """
        Handler for host leaving the network. Passes host port to the controller.
        :param ev: 
        :return: 
        """
        HandoverController.port_delete_handler(ev.port)

# Register own handover message wrapper for automatic packet parsing
ethernet.register_packet_type(HandoverMessageWrapper, CONTROL_MESSAGE_ETHER_TYPE)