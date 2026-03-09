import ipaddress

from cryptography import x509

SAN_PREFIXES = (
    ("email", x509.RFC822Name, lambda val: x509.RFC822Name(val)),
    ("dns", x509.DNSName, lambda val: x509.DNSName(val)),
    ("ip", x509.IPAddress, lambda val: x509.IPAddress(ipaddress.ip_address(val))),
    ("uri", x509.UniformResourceIdentifier, lambda val: x509.UniformResourceIdentifier(val))
)


def map_san(san: str) -> x509.GeneralName:
    their_prefix, value = san.split(":", 1)

    for prefix, _, factory in SAN_PREFIXES:
        if prefix == their_prefix:
            return factory(value)

    raise ValueError("No such Subject Alternative Name prefix is supported: " + their_prefix)


def unmap_sans(cert: x509.Certificate | x509.CertificateSigningRequest) -> list[str]:
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []

    out = []

    for general_name in san_ext.value:
        for prefix, cls, _ in SAN_PREFIXES:
            if isinstance(general_name, cls):
                out.append(f"{prefix}:{general_name.value}")
                break
        else:
            raise ValueError(f"Unsupported Subject Alternative Name type: "
                             f"{type(general_name).__name__}: {general_name}")

    return out
