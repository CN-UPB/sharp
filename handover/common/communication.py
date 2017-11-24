import requests
import json
from requests import ConnectionError


class ControllerCommunicator:
    """
    A basic controller API interface
    """
    HANDOVER_ENDPOINT = 'handover'

    def __init__(self, ip, port=None):
        self.ip = ip
        self.port = port
        self.address = ip
        if port:
            self.address += ':{port}'.format(port=port)

    def _get_address(self, endpoint):
        return 'http://{address}/{endpoint}'.format(address=self.address,
                                                    endpoint='/'.join([self.HANDOVER_ENDPOINT, endpoint]))

    def _get_param(self, val, idx):
        if type(val) is tuple or type(val) is list:
            return val[idx] if len(val) > idx else None
        else:
            return val

    def post(self, endpoint, data=None):
        return requests.post(self._get_address(endpoint), json=data)

    def delete(self, endpoint):
        return requests.delete(self._get_address(endpoint))

    def get(self, endpoint):
        return requests.get(self._get_address(endpoint))

    def register_switch(self, datapath_id, is_ingress):
        data = {'dpid': datapath_id,
                'position': ['egress', 'ingress'][is_ingress]}
        return self.post('switches', data=data)

    def register_vnf(self, ingress, egress):
        data = {'addresses': [self._get_param(ingress, 0), self._get_param(egress, 0)],
                'ports': [self._get_param(ingress, 1), self._get_param(egress, 1)]}
        resp = self.post('vnfs', data)
        if resp.status_code != 201:
            print("register_vnf failed with {}".format(resp.status_code))

    def add_handover_rule(self, vnf_id=0, priority=0, **kwargs):
        data = {'vnf_id': vnf_id,
                'priority': priority,
                'match': kwargs}
        resp = self.post('rules', data)
        if resp.status_code != 200:
            print("add_handover_rule failed with {}: {}".format(resp.status_code, resp.content))

    def remove_handover_rule(self, rule_id):
        resp = self.delete('rules/{}'.format(rule_id))
        if resp.status_code != 200:
            print("remove_handover_rule failed with {}: {}".format(resp.status_code, resp.content))

    def get_rules(self, switch_id=None):
        return self.get('rules{}'.format('/' + switch_id if switch_id else ''))

    def get_handover_statistics(self, handover_id):
        resp = self.get('handovers/{}'.format(handover_id))
        if resp.status_code == 404:
            return None
        return json.loads(resp.content)

    def is_ready(self):
        try:
            if self.get('ready'):
                return True
        except ConnectionError:
            return False
