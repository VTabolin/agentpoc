import sys

from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging

from neutron.common import utils
from neutron.common import config as common_config
from neutron.i18n import _LE, _LI, _LW
from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.agent.linux import ip_lib
from neutron.agent.common import config as agent_conf

LOG = logging.getLogger(__name__)
cfg.CONF.import_group('AGENT', 'vmware_conf')

def create_agent_config_map(config):
    """Create a map of agent config parameters.

    :param config: an instance of cfg.CONF
    :returns: a map of agent configuration parameters
    """
    try:
        bridge_mappings = utils.parse_mappings(config.ML2_VMWARE.network_maps)
    except ValueError as e:
        raise ValueError(_("Parsing network_maps failed: %s.") % e)

    kwargs = dict(
        vsphere_hostname=config.ML2_VMWARE.vsphere_hostname,
        vsphere_login=config.ML2_VMWARE.vsphere_login,
        vsphere_password=config.ML2_VMWARE.vsphere_password,
        bridge_mappings=bridge_mappings,
        polling_interval=config.AGENT.polling_interval,
        minimize_polling=config.AGENT.minimize_polling,
        tunnel_types=config.AGENT.tunnel_types,
        veth_mtu=config.AGENT.veth_mtu,
        enable_distributed_routing=config.AGENT.enable_distributed_routing,
        l2_population=config.AGENT.l2_population,
        arp_responder=config.AGENT.arp_responder,
        prevent_arp_spoofing=config.AGENT.prevent_arp_spoofing,
        quitting_rpc_timeout=config.AGENT.quitting_rpc_timeout,
    )
    return kwargs

class SimpleAgent(sg_rpc.SecurityGroupAgentRpcCallbackMixin):

    target = oslo_messaging.Target(version='1.2')

    def __init__(self, vsphere_hostname, vsphere_login, vsphere_password,
                 bridge_mappings, polling_interval, tunnel_types=None,
                 veth_mtu=None, l2_population=False,
                 enable_distributed_routing=False,
                 minimize_polling=False,
                 arp_responder=False,
                 prevent_arp_spoofing=True,
                 quitting_rpc_timeout=None):
        pass

def main():

    cfg.CONF.register_opts(ip_lib.OPTS)
    agent_conf.register_root_helper(cfg.CONF)
    common_config.init(sys.argv[1:])
    common_config.setup_logging()
    utils.log_opt_values(LOG)

    try:
        agent_config = create_agent_config_map(cfg.CONF)
    except ValueError as e:
        LOG.error(_LE('%s Agent terminated!'), e)
        sys.exit(1)

    print agent_config
    try:
        agent = SimpleAgent(**agent_config)
    except RuntimeError as e:
        LOG.error(_LE("%s Agent terminated!"), e)
        sys.exit(1)
    '''signal.signal(signal.SIGTERM, agent._handle_sigterm)

    # Start everything.
    LOG.info(_LI("Agent initialized successfully, now running... "))
    agent.daemon_loop()'''
