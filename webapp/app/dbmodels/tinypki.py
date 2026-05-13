from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional

from sqlalchemy.orm import RelationshipProperty
from sqlmodel import Field, SQLModel, Column, JSON, ARRAY, String
from sqlmodel import Integer, Relationship

from .stepca import X509Certificate


class EnumWithCoerce(Enum):
    @classmethod
    def coerce(cls, item):
        if isinstance(item, cls):
            return item

        return cls[item]


class KeygenFlow(EnumWithCoerce):
    # the private key is generated on the client side using Web Crypto API
    CLIENT_SIDE = "CLIENT_SIDE"
    # the private key is generated on the server (less secure but more compatible)
    SERVER_SIDE = "SERVER_SIDE"


class SubjectMode(EnumWithCoerce):
    # user is asked to provide the CN and DNS SANS when creating an invitation
    DEFAULT = "DEFAULT"
    # only one SAN DNS is allowed and it's automatically copied to CN
    SIMPLE_DNS = "SIMPLE_DNS"
    # the same but with email
    SIMPLE_EMAIL = "SIMPLE_EMAIL"


class InvitationStatus(EnumWithCoerce):
    CREATED = "CREATED"
    OPENED = "OPENED"
    LOCKED = "LOCKED"
    EXCEPTION = "EXCEPTION"
    ISSUED = "ISSUED"


class TinySystemMetadata(SQLModel, table=True):
    key: str = Field(primary_key=True)
    value: dict = Field(default_factory=dict, sa_column=Column(JSON))


class TinyJWKProvisioner(SQLModel, table=True):
    name: str = Field(primary_key=True)
    provisioner_jwe: str = Field()
    provisioner_jwe_kid: str = Field()
    is_default: bool = Field(default=False)
    registered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class TinyBlueprint(SQLModel, table=True):
    name: str = Field(primary_key=True)
    provisioner_name: str = Field(index=True, foreign_key="tinyjwkprovisioner.name")
    not_before: str = Field()
    not_after_days: int = Field()
    invitation_validity_days: int = Field()
    key_algorithm: str = Field()
    keygen_flow: KeygenFlow = Field()
    subject_mode: SubjectMode = Field()

    jwk_provisioner: Optional["TinyJWKProvisioner"] = Relationship()


class TinyInvitation(SQLModel, table=True):
    id: int = Field(sa_column=Column(Integer, primary_key=True, autoincrement=True))
    submit_nonce: str = Field(unique=True)

    redeem_code_hash: str = Field(unique=True)
    blueprint_name: str = Field(index=True, foreign_key="tinyblueprint.name")

    subject_common_name: str = Field(index=True)
    subject_alt_names: List[str] = Field(sa_column=Column(ARRAY(String), index=True), default_factory=lambda: [])
    template_data: dict = Field(default_factory=dict, sa_column=Column(JSON))
    not_after_days: int = Field()

    status: InvitationStatus = Field()
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = Field()

    serial_no: Optional[str] = Field(unique=True, nullable=True, default=None)
    keygen_flow: Optional[KeygenFlow] = Field(nullable=True)
    error_message: Optional[str] = Field(nullable=True, default=None)

    blueprint: Optional["TinyBlueprint"] = Relationship()
    x509_cert: Optional["X509Certificate"] = Relationship(
        sa_relationship=RelationshipProperty(
            "X509Certificate",
            back_populates="tiny_invitation",
            primaryjoin="TinyInvitation.serial_no == X509Certificate.serial_no",
            foreign_keys="[TinyInvitation.serial_no]",
            uselist=False)
    )
