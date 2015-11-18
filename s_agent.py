import sys

from oslo_config import cfg
from oslo_log import log as logging

from neutron.agent.common import config as agent_conf
from neutron.common import utils
from neutron.agent.linux import ip_lib
from neutron.common import config as common_config

LOG = logging.getLogger(__name__)
#cfg.CONF.import_group('AGENT', 'neutron.plugins.openvswitch.common.config')
cfg.CONF.import_group('AGENT', 'vmware_conf')

def create_agent_config_map(config):
    """Create a map of agent config parameters.

    :param config: an instance of cfg.CONF
    :returns: a map of agent configuration parameters
    """
    try:
        bridge_mappings = utils.parse_mappings(config.OVS.bridge_mappings)
    except ValueError as e:
        raise ValueError(_("Parsing bridge_mappings failed: %s.") % e)

    kwargs = dict(
        integ_br=config.OVS.integration_bridge,
        tun_br=config.OVS.tunnel_bridge,
        local_ip=config.OVS.local_ip,
        bridge_mappings=bridge_mappings,
        polling_interval=config.AGENT.polling_interval,
        minimize_polling=config.AGENT.minimize_polling,
        tunnel_types=config.AGENT.tunnel_types,
        veth_mtu=config.AGENT.veth_mtu,
        enable_distributed_routing=config.AGENT.enable_distributed_routing,
        l2_population=config.AGENT.l2_population,
        arp_responder=config.AGENT.arp_responder,
        prevent_arp_spoofing=config.AGENT.prevent_arp_spoofing,
        use_veth_interconnection=config.OVS.use_veth_interconnection,
        quitting_rpc_timeout=config.AGENT.quitting_rpc_timeout,
        vmware=config.ML2_VMWARE.test
    )

    # Verify the tunnel_types specified are valid
    for tun in kwargs['tunnel_types']:
        if tun not in constants.TUNNEL_NETWORK_TYPES:
            msg = _('Invalid tunnel type specified: %s'), tun
            raise ValueError(msg)
        if not kwargs['local_ip']:
            msg = _('Tunneling cannot be enabled without a valid local_ip.')
            raise ValueError(msg)


    '''kwargs = dict(
        polling_interval=config.AGENT.polling_interval,
        minimize_polling=config.AGENT.minimize_polling,
        tunnel_types=config.AGENT.tunnel_types,
        veth_mtu=config.AGENT.veth_mtu,
        enable_distributed_routing=config.AGENT.enable_distributed_routing,
        l2_population=config.AGENT.l2_population,
        arp_responder=config.AGENT.arp_responder,
        prevent_arp_spoofing=config.AGENT.prevent_arp_spoofing,
        quitting_rpc_timeout=config.AGENT.quitting_rpc_timeout
    )'''

    return kwargs

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
    '''try:
        agent = SimpleAgent(**agent_config)
    except RuntimeError as e:
        LOG.error(_LE("%s Agent terminated!"), e)
        sys.exit(1)
    signal.signal(signal.SIGTERM, agent._handle_sigterm)

    # Start everything.
    LOG.info(_LI("Agent initialized successfully, now running... "))
    agent.daemon_loop()'''
