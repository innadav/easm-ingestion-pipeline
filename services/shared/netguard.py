import asyncio
import ipaddress
import socket


def is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


async def host_is_public(host: str) -> bool:
    """True only when the host resolves and every resolved address is publicly routable."""
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(
            host, None, type=socket.SOCK_STREAM
        )
    except OSError:
        return False
    addresses = {info[4][0] for info in infos}
    return bool(addresses) and all(is_public_ip(address) for address in addresses)
