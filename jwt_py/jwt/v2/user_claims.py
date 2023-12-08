from dataclasses import dataclass, field
from typing import Final

import nkeys.nkeys

from jwt.nkeys_ext import Decode
from jwt.v2.claims import _claim_data_config, ClaimsData, GenericFields, PrefixByte, UserClaim
from jwt.v2.types import Limits, Permissions, UserLimits
from jwt.v2.validation import ValidationResults

ConnectionTypeStandard: Final[str] = "STANDARD"
ConnectionTypeWebsocket: Final[str] = "WEBSOCKET"
ConnectionTypeLeafnode: Final[str] = "LEAFNODE"
ConnectionTypeLeafnodeWS: Final[str] = "LEAFNODE_WS"
ConnectionTypeMqtt: Final[str] = "MQTT"
ConnectionTypeMqttWS: Final[str] = "MQTT_WS"


@dataclass
class UserPermissionLimits(Permissions, Limits):
    bearer_token: bool = None
    allowed_connection_types: list[str] = None

    def as_user_permission_limits(self) -> "UserPermissionLimits":
        return UserPermissionLimits(
            bearer_token=self.bearer_token,
            allowed_connection_types=self.allowed_connection_types,
            pub=self.pub,
            sub=self.sub,
            resp=self.resp,
            src=self.src,
            times=self.times,
            locale=self.locale,
            subs=self.subs,
            data=self.data,
            payload=self.payload
        )


@dataclass
class _User(UserPermissionLimits):
    """ NOTE: Class created due to dataclasses required argument
    if arguments of this class are defined in `User` class, that will cause
    `Non-default argument(s) follows default argument(s) defined in 'UserPermissionLimits', 'Permissions', 'Limits' `
    """
    issuer_account: str = field(default="", metadata=_claim_data_config)


@dataclass
class User(GenericFields, _User):
    """ User defines the user-specific data in a user JWT """

    def validate(self, vr: ValidationResults) -> None:
        self.as_permissions().validate(vr)
        self.as_limits().validate(vr)


@dataclass
class UserClaims(ClaimsData):
    nats: User = field(default_factory=User)

    def __post_init__(self):
        from jwt.v2.account_claims import NatsLimits

        if self.sub == "":
            raise ValueError("subject is required")

        self.nats.user_limits = UserLimits()
        self.nats.nats_limits = NatsLimits()

    def set_scoped(self, t: bool) -> None:
        if t:
            self.nats.user_permissions_limits = UserPermissionLimits()
        else:
            self.nats.user_limits = UserLimits()
            self.nats.nats_limits = UserLimits()

    def has_empty_permissions(self) -> bool:
        return self.nats.as_user_permission_limits() == UserPermissionLimits()

    def encode(self, pair: nkeys.KeyPair) -> str: # noqa
        """
        Raises:
            ValueError: if Decode fails
        :param pair:
        :return:
        """
        # nkeys.IsValidPublicUserKey
        Decode(nkeys.PREFIX_BYTE_USER, self.sub.encode())

        self.nats.type = UserClaim
        return super().encode(pair, self)

    def validate(self, vr: ValidationResults):
        super().validate(vr)
        self.nats.validate(vr)

    def expected_prefixes(self) -> list[PrefixByte]:
        return [nkeys.PREFIX_BYTE_USER]

    def claims(self) -> ClaimsData:
        return self

    def payload(self) -> User:
        return self.nats

    def is_bearer_token(self) -> bool:
        return self.nats.bearer_token

    def get_tags(self) -> list[str]:
        return self.nats.tags
