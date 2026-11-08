
import ipaddress
import socket
import ssl


class SafeNetworkError(Exception):
    """Raised when a network destination is invalid or unsafe."""
    pass


def resolve_public_addresses(hostname: str, port: int):
    """
    Resolve a hostname and reject the destination if any resolved
    address is not globally routable.

    Returns validated socket address records.
    """

    if not hostname or not isinstance(hostname, str):
        raise SafeNetworkError("Invalid hostname.")

    hostname = hostname.strip().rstrip(".")

    if not hostname or any(char.isspace() for char in hostname):
        raise SafeNetworkError("Invalid hostname.")

    if "%" in hostname:
        raise SafeNetworkError("Scoped IP addresses are not allowed.")

    try:
        # Handle IP literals directly.
        ip = ipaddress.ip_address(hostname)

        if not ip.is_global:
            raise SafeNetworkError(
                "Private or restricted IP addresses are blocked."
            )

        if isinstance(ip, ipaddress.IPv4Address):
            return [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    socket.IPPROTO_TCP,
                    (str(ip), port)
                )
            ]

        return [
            (
                socket.AF_INET6,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                (str(ip), port, 0, 0)
            )
        ]

    except ValueError:
        pass

    # Convert internationalized domain names to ASCII.
    try:
        hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError:
        raise SafeNetworkError("Invalid domain name.")

    try:
        records = socket.getaddrinfo(
            hostname,
            port,
            type=socket.SOCK_STREAM
        )
    except socket.gaierror:
        raise SafeNetworkError("Website domain could not be resolved.")

    if not records:
        raise SafeNetworkError("No network addresses found.")

    validated = []
    seen = set()

    for family, socktype, proto, _, sockaddr in records:

        address = sockaddr[0]

        if "%" in address:
            raise SafeNetworkError(
                "Scoped IP addresses are not allowed."
            )

        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            raise SafeNetworkError("Invalid DNS response.")

        # Reject the entire result if even one address is restricted.
        if not ip.is_global:
            raise SafeNetworkError(
                "Private or restricted addresses are blocked."
            )

        key = (family, str(ip), port)

        if key not in seen:
            seen.add(key)

            validated.append(
                (family, socktype, proto, sockaddr)
            )

    if not validated:
        raise SafeNetworkError("No valid public addresses found.")

    return validated


def open_safe_connection(
    hostname: str,
    port: int,
    timeout: int = 5,
    use_tls: bool = False
):
    """
    Connect directly to a previously validated IP address.

    TLS connections retain certificate-chain and hostname verification.
    The hostname is never resolved again during the connection.
    """

    addresses = resolve_public_addresses(hostname, port)

    last_error = None

    for family, socktype, proto, sockaddr in addresses:

        connection = None

        try:
            connection = socket.socket(
                family,
                socktype,
                proto
            )

            connection.settimeout(timeout)

            # Connect directly to the validated IP.
            connection.connect(sockaddr)

            if use_tls:

                context = ssl.create_default_context()

                connection = context.wrap_socket(
                    connection,
                    server_hostname=hostname.rstrip(".")
                )

            return connection

        except (OSError, ssl.SSLError) as error:

            last_error = error

            if connection is not None:
                connection.close()

    if last_error is not None:
        raise last_error

    raise SafeNetworkError("Could not establish a safe connection.")
