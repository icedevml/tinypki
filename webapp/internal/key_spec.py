from cryptography import x509
from cryptography.hazmat.bindings._rust import ObjectIdentifier
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.hashes import SHA256, SHA384, SHA512

KEY_SPEC_CLASSES = {}


def key_spec(algorithm):
    global KEY_SPEC_CLASSES

    def wrapper(func):
        KEY_SPEC_CLASSES[algorithm] = func
        return func

    return wrapper


def _resolve_mapping_two_keys(mapping, key0, key1):
    for record in mapping:
        if record[0] != key0:
            continue

        if record[1] != key1:
            continue

        return record

    raise ValueError(f"Unknown value: {key0}, {key1}")


def _resolve_mapping_single_key(mapping, key0):
    for record in mapping:
        if record[0] != key0:
            continue

        return record

    raise ValueError(f"Unknown value: {key0}")


class KeySpec:
    _MAP = []

    def __init__(self, algorithm, **kwargs):
        self.algorithm = algorithm

    def generate_private_key(self):
        raise NotImplemented("Base class KeySpec is abstract.")

    def verify_csr(self, csr: x509.CertificateSigningRequest):
        raise NotImplemented("Base class KeySpec is abstract.")

    def create_hash_instance(self):
        raise NotImplemented("Base class KeySpec is abstract.")

    def to_dict(self):
        raise NotImplemented("Base class KeySpec is abstract.")

    @staticmethod
    def from_string(key_spec_str: str):
        parts = key_spec_str.split("/")
        algorithm_name = parts[0]

        if algorithm_name not in KEY_SPEC_CLASSES:
            raise ValueError("No such algorithm is supported: " + algorithm_name)

        cls = KEY_SPEC_CLASSES[algorithm_name]
        return cls(*parts)


class KeySpecWithHash(KeySpec):
    _MAP = [
        ("SHA-256", SHA256),
        ("SHA-384", SHA384),
        ("SHA-512", SHA512),
    ]

    def __init__(self, *, hash_algorithm, algorithm, **kwargs):
        super().__init__(algorithm=algorithm, **kwargs)
        self.hash_algorithm, self.hash_algorithm_cls = _resolve_mapping_single_key(KeySpecWithHash._MAP, hash_algorithm)

    def create_hash_instance(self):
        return self.hash_algorithm_cls()

    def _verify_hash(self, csr: x509.CertificateSigningRequest):
        if type(csr.signature_hash_algorithm) != self.hash_algorithm_cls:
            raise ValueError(f"Incorrect hash algorithm in CSR.\n"
                             f"  Actual: {csr.signature_hash_algorithm.__class__}.\n"
                             f"  Expected: {self.hash_algorithm_cls}")


@key_spec("RSASSA-PKCS1-v1_5")
@key_spec("RSA-PSS")
class RSAKeySpec(KeySpecWithHash):
    _MAP = [
        ("RSASSA-PKCS1-v1_5", "SHA-256", ObjectIdentifier("1.2.840.113549.1.1.11")),
        ("RSASSA-PKCS1-v1_5", "SHA-384", ObjectIdentifier("1.2.840.113549.1.1.12")),
        ("RSASSA-PKCS1-v1_5", "SHA-512", ObjectIdentifier("1.2.840.113549.1.1.13")),
        ("RSA-PSS", "SHA-256", ObjectIdentifier("1.2.840.113549.1.1.10")),
        ("RSA-PSS", "SHA-384", ObjectIdentifier("1.2.840.113549.1.1.10")),
        ("RSA-PSS", "SHA-512", ObjectIdentifier("1.2.840.113549.1.1.10")),
    ]

    def __init__(self, algorithm, key_size, hash_algorithm):
        self.algorithm, self.hash_algorithm, self.algorithm_oid = _resolve_mapping_two_keys(RSAKeySpec._MAP, algorithm,
                                                                                            hash_algorithm)
        super().__init__(algorithm=algorithm, hash_algorithm=hash_algorithm)

        self.key_size = int(key_size)

    def generate_private_key(self) -> RSAPrivateKey:
        return rsa.generate_private_key(public_exponent=65537, key_size=self.key_size)

    def verify_csr(self, csr: x509.CertificateSigningRequest):
        self._verify_hash(csr)

        if csr.signature_algorithm_oid != self.algorithm_oid:
            raise ValueError(f"Incorrect signature algorithm in CSR.\n"
                             f"  Actual: {csr.signature_algorithm_oid}.\n"
                             f"  Expected: {self.algorithm_oid}")

        if csr.public_key().key_size != self.key_size:
            raise ValueError(f"Incorrect key size in CSR.\n"
                             f"  Actual: {csr.public_key().key_size}.\n"
                             f"  Expected: {self.key_size}")

    def to_dict(self):
        return {
            "algorithm": self.algorithm,
            "key_size": self.key_size,
            "hash_algorithm": self.hash_algorithm,
        }

    def to_string(self):
        return f"{self.algorithm}/{self.key_size}/{self.hash_algorithm}"


@key_spec("ECDSA")
class ECDSAKeySpec(KeySpecWithHash):
    _MAP_CURVE = [
        ("P-256", "secp256r1", ec.SECP256R1),
        ("P-384", "secp384r1", ec.SECP384R1),
        ("P-521", "secp521r1", ec.SECP521R1),
    ]

    _MAP_ECDSA_HASH = [
        ("SHA-256", ObjectIdentifier("1.2.840.10045.4.3.2")),
        ("SHA-384", ObjectIdentifier("1.2.840.10045.4.3.3")),
        ("SHA-512", ObjectIdentifier("1.2.840.10045.4.3.4")),
    ]

    def __init__(self, algorithm, curve, hash_algorithm):
        if algorithm != "ECDSA":
            raise ValueError(f"Unexpected algorithm: {algorithm}")

        super().__init__(algorithm="ECDSA", hash_algorithm=hash_algorithm)

        self.curve, self.pyca_curve_name, self.pyca_curve_cls = _resolve_mapping_single_key(ECDSAKeySpec._MAP_CURVE,
                                                                                            curve)
        self.hash_algorithm, self.signature_algorithm_oid = _resolve_mapping_single_key(ECDSAKeySpec._MAP_ECDSA_HASH,
                                                                                        hash_algorithm)

    def generate_private_key(self) -> EllipticCurvePrivateKey:
        return ec.generate_private_key(self.pyca_curve_cls())

    def verify_csr(self, csr: x509.CertificateSigningRequest):
        self._verify_hash(csr)

        if csr.signature_algorithm_oid != self.signature_algorithm_oid:
            raise ValueError(f"Incorrect signature algorithm OID in CSR.\n"
                             f"  Actual: {csr.signature_algorithm_oid}.\n"
                             f"  Expected: {self.signature_algorithm_oid}")

        if csr.public_key().curve.name != self.pyca_curve_name:
            raise ValueError(f"Incorrect curve name in CSR.\n"
                             f"  Actual: {csr.public_key().curve.name}.\n"
                             f"  Expected: {self.pyca_curve_name}")

    def to_dict(self):
        return {
            "algorithm": self.algorithm,
            "curve": self.curve,
            "hash_algorithm": self.hash_algorithm,
        }

    def to_string(self):
        return f"{self.algorithm}/{self.curve}/{self.hash_algorithm}"


@key_spec("Ed25519")
class Ed25519KeySpec(KeySpec):
    def __init__(self, algorithm):
        if algorithm != "Ed25519":
            raise ValueError(f"Unexpected algorithm: {algorithm}")

        super().__init__(algorithm=algorithm)

        self.signature_algorithm_oid = ObjectIdentifier("1.3.101.112")

    def create_hash_instance(self):
        return None

    def generate_private_key(self) -> Ed25519PrivateKey:
        return Ed25519PrivateKey.generate()

    def verify_csr(self, csr: x509.CertificateSigningRequest):
        if csr.signature_algorithm_oid != self.signature_algorithm_oid:
            raise ValueError(f"Incorrect signature algorithm in CSR.\n"
                             f"  Actual: {csr.signature_algorithm_oid}.\n"
                             f"  Expected: {self.signature_algorithm_oid}")

    def to_dict(self):
        return {
            "algorithm": self.algorithm,
        }

    def to_string(self):
        return f"{self.algorithm}"


SUPPORTED_KEY_SPECS = [
    # Common
    ECDSAKeySpec(algorithm="ECDSA", curve="P-256", hash_algorithm="SHA-256"),
    RSAKeySpec(algorithm="RSASSA-PKCS1-v1_5", key_size=2048, hash_algorithm="SHA-256"),
    RSAKeySpec(algorithm="RSASSA-PKCS1-v1_5", key_size=4096, hash_algorithm="SHA-256"),

    # Other RSA
    RSAKeySpec(algorithm="RSASSA-PKCS1-v1_5", key_size=2048, hash_algorithm="SHA-256"),
    RSAKeySpec(algorithm="RSASSA-PKCS1-v1_5", key_size=3072, hash_algorithm="SHA-256"),
    RSAKeySpec(algorithm="RSASSA-PKCS1-v1_5", key_size=3072, hash_algorithm="SHA-384"),
    RSAKeySpec(algorithm="RSASSA-PKCS1-v1_5", key_size=4096, hash_algorithm="SHA-256"),
    RSAKeySpec(algorithm="RSASSA-PKCS1-v1_5", key_size=4096, hash_algorithm="SHA-384"),
    RSAKeySpec(algorithm="RSA-PSS", key_size=2048, hash_algorithm="SHA-256"),
    RSAKeySpec(algorithm="RSA-PSS", key_size=3072, hash_algorithm="SHA-256"),
    RSAKeySpec(algorithm="RSA-PSS", key_size=3072, hash_algorithm="SHA-384"),
    RSAKeySpec(algorithm="RSA-PSS", key_size=4096, hash_algorithm="SHA-256"),
    RSAKeySpec(algorithm="RSA-PSS", key_size=4096, hash_algorithm="SHA-384"),

    # Other ECDSA
    ECDSAKeySpec(algorithm="ECDSA", curve="P-384", hash_algorithm="SHA-256"),
    ECDSAKeySpec(algorithm="ECDSA", curve="P-384", hash_algorithm="SHA-384"),
    ECDSAKeySpec(algorithm="ECDSA", curve="P-521", hash_algorithm="SHA-512"),

    # Ed25519
    Ed25519KeySpec(algorithm="Ed25519"),
]

SUPPORTED_KEY_SPECS_STR = list(map(lambda spec: spec.to_string(), SUPPORTED_KEY_SPECS))
