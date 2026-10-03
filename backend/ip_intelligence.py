import ipaddress
import socket
import requests


def resolve_hostname(hostname: str):
    """
    Resolve a hostname to unique IPv4/IPv6 addresses.

    This performs DNS resolution only.
    It does NOT open or visit the target website.
    """

    result = {
        "resolved": False,
        "hostname": hostname or "",
        "ip_addresses": [],
        "public_addresses": [],
        "private_addresses": [],
        "error": None,
    }

    if not hostname:
        result["error"] = "No hostname supplied."
        return result

    try:
        answers = socket.getaddrinfo(
            hostname,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
        )

        addresses = sorted({
            item[4][0]
            for item in answers
            if item and item[4]
        })

        result["ip_addresses"] = addresses
        result["resolved"] = bool(addresses)

        for address in addresses:

            try:
                ip = ipaddress.ip_address(address)

                if (
                    ip.is_private
                    or ip.is_loopback
                    or ip.is_link_local
                ):
                    result["private_addresses"].append(address)

                else:
                    result["public_addresses"].append(address)

            except ValueError:
                continue

    except socket.gaierror:

        result["error"] = (
            "Hostname could not be resolved."
        )

    except socket.timeout:

        result["error"] = (
            "DNS resolution timed out."
        )

    except Exception as exc:

        result["error"] = (
            f"DNS resolution failed: {exc}"
        )

    return result


def geolocate_ip(ip: str):
    """
    Retrieve approximate geolocation and network
    information for a public IP address.

    Uses ipapi.co over HTTPS.
    """

    result = {
        "available": False,
        "ip": ip,
        "country": None,
        "country_code": None,
        "region": None,
        "city": None,
        "postal": None,
        "timezone": None,
        "latitude": None,
        "longitude": None,
        "asn": None,
        "organization": None,
        "error": None,
    }

    if not ip:

        result["error"] = (
            "No public IP available for geolocation."
        )

        return result

    try:

        ip_obj = ipaddress.ip_address(ip)

        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
        ):

            result["error"] = (
                "Private/local IP addresses are "
                "not geolocated."
            )

            return result

    except ValueError:

        result["error"] = (
            "Invalid IP address."
        )

        return result

    try:

        response = requests.get(
            f"https://ipapi.co/{ip}/json/",
            headers={
                "User-Agent":
                    "AEGIS-URL-Scanner/1.0"
            },
            timeout=6,
        )

        if response.status_code != 200:

            result["error"] = (
                "IP geolocation service returned "
                f"HTTP {response.status_code}."
            )

            return result

        data = response.json()

        if data.get("error"):

            result["error"] = (
                data.get("reason")
                or
                "IP geolocation service "
                "rejected the lookup."
            )

            return result

        result.update(
            {
                "available": True,

                "country":
                    data.get("country_name"),

                "country_code":
                    data.get("country_code")
                    or
                    data.get("country"),

                "region":
                    data.get("region"),

                "city":
                    data.get("city"),

                "postal":
                    data.get("postal"),

                "timezone":
                    data.get("timezone"),

                "latitude":
                    data.get("latitude"),

                "longitude":
                    data.get("longitude"),

                "asn":
                    data.get("asn"),

                "organization":
                    data.get("org"),
            }
        )

    except requests.RequestException:

        result["error"] = (
            "IP geolocation service is "
            "currently unavailable."
        )

    except ValueError:

        result["error"] = (
            "IP geolocation service returned "
            "invalid JSON."
        )

    except Exception as exc:

        result["error"] = (
            f"IP geolocation failed: {exc}"
        )

    return result


def analyze_host_ip(hostname: str):
    """
    Resolve the hostname and geolocate the
    first public IP address.
    """

    dns = resolve_hostname(hostname)

    public_ips = dns.get(
        "public_addresses",
        []
    )

    if public_ips:

        geo = geolocate_ip(
            public_ips[0]
        )

    else:

        geo = geolocate_ip("")

    return {

        "dns": dns,

        "primary_ip":
            public_ips[0]
            if public_ips
            else None,

        "geolocation":
            geo,

        "note":
            "IP geolocation describes the approximate "
            "location of the resolved server/CDN IP; "
            "it does not identify the physical location "
            "of the website operator."
    }