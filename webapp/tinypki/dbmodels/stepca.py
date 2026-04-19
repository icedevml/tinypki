from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy.orm import RelationshipProperty
from sqlmodel import Field, SQLModel, Column, JSON, ARRAY, String
from sqlmodel import Relationship


class X509CertificateRevocation(SQLModel, table=True):
    serial_no: str = Field(primary_key=True)
    indexed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    provisioner_id: str = Field(index=True)
    reason_code: int = Field(index=True)
    reason: str = Field(index=True)
    revoked_at: datetime = Field(index=True)
    expires_at: datetime = Field(index=True)
    token_id: str = Field(index=True)
    mtls: bool = Field(index=True)
    acme: bool = Field(index=True)

    x509_cert: Optional["X509Certificate"] = Relationship(
        sa_relationship=RelationshipProperty(
            "X509Certificate",
            back_populates="x509_cert_revocation",
            primaryjoin="X509CertificateRevocation.serial_no == X509Certificate.serial_no",
            foreign_keys="[X509CertificateRevocation.serial_no]",
            uselist=False)
    )


class X509CertificateData(SQLModel, table=True):
    serial_no: str = Field(primary_key=True)
    indexed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    provisioner_id: str = Field(index=True)
    provisioner_name: str = Field(index=True)
    provisioner_type: str = Field()
    raw_issuance_data: dict = Field(default_factory=dict, sa_column=Column(JSON))

    x509_cert: Optional["X509Certificate"] = Relationship(
        sa_relationship=RelationshipProperty(
            "X509Certificate",
            back_populates="x509_cert_data",
            primaryjoin="X509CertificateData.serial_no == X509Certificate.serial_no",
            foreign_keys="[X509CertificateData.serial_no]",
            uselist=False)
    )


class X509Certificate(SQLModel, table=True):
    serial_no: str = Field(
        primary_key=True,
        schema_extra={"examples": ["126642438540059140742215468660770163299"]}
    )
    indexed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        schema_extra={"examples": ["2026-02-26T14:44:10.454905"]}
    )

    subject_name: Optional[str] = Field(
        index=True,
        schema_extra={"examples": ["CN=janusz@example.com"]}
    )
    subject_alt_names: Optional[List[str]] = Field(
        sa_column=Column(
            ARRAY(String),
            index=True,
            nullable=True
        ),
        default=None,
        schema_extra={"examples": [["email:janusz@example.com"]]}
    )
    key_usage: Optional[List[str]] = Field(
        sa_column=Column(
            ARRAY(String),
            index=True,
            nullable=True
        ),
        default=None,
        schema_extra={"examples": [["digitalSignature"]]}
    )
    ext_key_usage: Optional[List[str]] = Field(
        sa_column=Column(
            ARRAY(String),
            index=True,
            nullable=True
        ),
        default=None,
        schema_extra={"examples": [["serverAuth", "clientAuth"]]}
    )
    issuer_name: str = Field(
        index=True,
        schema_extra={"examples": ["CN=Smallstep Intermediate CA,O=Smallstep"]}
    )
    fingerprint_sha256: str = Field(
        unique=True,
        max_length=64,
        schema_extra={"examples": ["e394e938cd6d6ba2a88eb680fafccc364381c143e90e1d7ba2b8ef713d9937a5"]}
    )
    time_not_before: datetime = Field(
        index=True,
        schema_extra={"examples": ["2026-02-26T14:43:14"]}
    )
    time_not_after: datetime = Field(
        index=True,
        schema_extra={"examples": ["2026-02-27T14:43:14"]}
    )
    cert_pem: str = Field(
        unique=True,
        schema_extra={"examples": ["-----BEGIN CERTIFICATE-----\nMIICMjCCAdigAwIBAgIQX0ZyS0w3R6ZLP3eC38dKYzAKBggqhkjOPQQDAjA4MRIw\nEAYDVQQKEwlTbWFsbHN0ZXAxIjAgBgNVBAMTGVNtYWxsc3RlcCBJbnRlcm1lZGlh\ndGUgQ0EwHhcNMjYwMjI2MTQ0MzE0WhcNMjYwMjI3MTQ0MzE0WjAdMRswGQYDVQQD\nDBJqYW51c3pAZXhhbXBsZS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQb\nT9xkJobixKaeSaBw18tmPc9Zq602AuwFAYWFP3Dm63NrOEWz/8g9HyVi50Y+cdyB\nXo3YLxgubcZpH6xbfu6Bo4HeMIHbMA4GA1UdDwEB/wQEAwIHgDAdBgNVHSUEFjAU\nBggrBgEFBQcDAQYIKwYBBQUHAwIwHQYDVR0OBBYEFHgJnrhzcqNwMDoD/fZO66hS\nJpftMB8GA1UdIwQYMBaAFFjG8V0IGutqe79IlUmjtyUw3PmSMB0GA1UdEQQWMBSB\nEmphbnVzekBleGFtcGxlLmNvbTBLBgwrBgEEAYKkZMYoQAEEOzA5AgEBBAd0aW55\ncGtpBCtXQ19RRXFFZFdrcDg5TFdqa19ST2FxVkZuVkFFM2VlekZwTTFGem13S2kw\nMAoGCCqGSM49BAMCA0gAMEUCIQCf8885pD0+VCgrDPp2HWj7P6l4fRcYGuqYR7K1\nOZV41QIgX0+18PXtZbLPKIwD+dZl5ymd2OUsVxU/4aban4XUT3U=\n-----END CERTIFICATE-----\n"]}
    )

    x509_cert_revocation: Optional[X509CertificateRevocation] = Relationship(
        sa_relationship=RelationshipProperty(
            "X509CertificateRevocation",
            back_populates="x509_cert",
            primaryjoin="X509Certificate.serial_no == X509CertificateRevocation.serial_no",
            foreign_keys="[X509CertificateRevocation.serial_no]",
            uselist=False)
    )
    x509_cert_data: Optional[X509CertificateData] = Relationship(
        sa_relationship=RelationshipProperty(
            "X509CertificateData",
            back_populates="x509_cert",
            primaryjoin="X509Certificate.serial_no == X509CertificateData.serial_no",
            foreign_keys="[X509CertificateData.serial_no]",
            uselist=False)
    )
    tiny_invitation: Optional["TinyInvitation"] = Relationship(
        sa_relationship=RelationshipProperty(
            "TinyInvitation",
            back_populates="x509_cert",
            primaryjoin="X509Certificate.serial_no == TinyInvitation.serial_no",
            foreign_keys="[TinyInvitation.serial_no]",
            uselist=False)
    )


class ACMEAccount(SQLModel, table=True):
    object_id: str = Field(primary_key=True)
    indexed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    data: dict = Field(default_factory=dict, sa_column=Column(JSON))


class ACMECert(SQLModel, table=True):
    object_id: str = Field(primary_key=True)
    indexed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    data: dict = Field(default_factory=dict, sa_column=Column(JSON))
