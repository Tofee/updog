import socket
from zeroconf import IPVersion, ServiceInfo, Zeroconf

ipStr = ''


def get_ip():
    global ipStr
    if ipStr != '':
        return ipStr

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except:
        IP = '127.0.0.1'
    finally:
        s.close()
    ipStr = IP
    return IP
    
    
# Zeroconf Utilities


def get_service_info(code):
    r"""Get service information for an Airshare service.
    Parameters
    ----------
    code : str
        Identifying code for the Airshare service.
    Returns
    -------
    info : zeroconf.ServiceInfo
        Details of the Airshare service.
    """
    zeroconf = Zeroconf(ip_version=IPVersion.V4Only)
    service = "_updog._http._tcp.local."
    info = zeroconf.get_service_info(service, code + service)
    return info


def register_service(code, port):
    r"""Registers an Airshare Multicast-DNS service based in the local network.
    Parameters
    ----------
    code : str
        Identifying code for the Airshare service.
    addresses : list
        List of local network IP Addresses for the service.
    port : int
        Port number for the Airshare service's server.
    Returns
    -------
    info : zeroconf.ServiceInfo
        Details of the Airshare service.
    """
    zeroconf = Zeroconf(ip_version=IPVersion.V4Only)
    service = "_updog._http._tcp.local."    
    ip = [socket.inet_aton(get_ip())]
    info = ServiceInfo(
        service,
        code + service,
        addresses=ip, # addresses,
        port=port,
        server=code + ".local."
    )
    zeroconf.register_service(info)
    return info
