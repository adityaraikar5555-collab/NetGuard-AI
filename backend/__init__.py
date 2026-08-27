"""
Backend package for the Network Anomaly Detection project.
"""

# Force IPv4-only for urllib3/requests. Windows DNS returns a NAT64 IPv6
# address (64:ff9b::...) first, which is unreachable on many networks and
# causes every HTTP call to hang until fallback. This makes requests fast.
try:
    import urllib3.util.connection as _uc

    _uc.HAS_IPV6 = False
    if hasattr(_uc, "allowed_gai_family") and hasattr(_uc, "ALLOWED_GAI_FAMILIES"):
        import socket as _socket

        _uc.ALLOWED_GAI_FAMILIES = (_socket.AF_INET,)
except Exception:
    pass