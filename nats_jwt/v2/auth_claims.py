#    Copyright 2024 Seznam.cz, a.s.
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final, Optional

import nkeys
from dataclasses_json import config, dataclass_json

from nats_jwt.nkeys_ext import Decode, keypair_from_pubkey

from nats_jwt.v2.claims import  ClaimsData, GenericFields, PrefixByte, AuthorizationResponseClaim, AuthorizationRequestClaim, ClaimType
from nats_jwt.v2.validation import ValidationResults


@dataclass
class _AuthResponseData():
    jwt: str = field(default="")
    error: Optional[str] = field(default=None)
    issuer_account: Optional[str] = field(default=None)


@dataclass
class AuthResponseData(GenericFields,_AuthResponseData):
    def validate(self, vr: ValidationResults) -> None:
        pass



@dataclass
class AuthResponseClaims(ClaimsData):
    nats: AuthResponseData = field(default_factory=AuthResponseData)

    def __post_init__(self):
        if self.sub == "":
            raise ValueError("subject is required")

    def claim_type(self):
        return AuthorizationResponseClaim

    def encode(self, pair: nkeys.KeyPair) -> str: # noqa
        """
        Raises:
            ValueError: if Decode fails
        :param pair:
        :return:
        """
        # nkeys.IsValidPublicUserKey
        Decode(nkeys.PREFIX_BYTE_USER, self.sub.encode())

        self.nats.type = AuthorizationResponseClaim
        return super().encode(pair, self)

    def validate(self, vr: ValidationResults):
        super().validate(vr)
        self.nats.validate(vr)

    def expected_prefixes(self) -> list[PrefixByte]:
        return [nkeys.PREFIX_BYTE_USER]

    def claims(self) -> ClaimsData:
        return self

    def payload(self) -> AuthResponseData:
        return self.nats


@dataclass_json
@dataclass
class ServerId():
    id: str = field(default="")
    name: str = field(default="")
    host: str = field(default="")
    version: str = field(default="")

@dataclass_json
@dataclass
class ClientInfo():
    host : str = field(default="")
    id : int = field(default=0)
    user: str = field(default="")
    name: str = field(default="")
    kind: str = field(default="")
    type: str = field(default="")

@dataclass_json
@dataclass
class ConnectOpts():
    user: str =  field(default="")
    password: str = field(default="", metadata=config(field_name="pass"))
    name: str = field(default="")
    lang: str = field(default="")
    version: str = field(default="")
    protocol: int = field(default=0)





@dataclass
class AuthRequestData(GenericFields):
    server_id: ServerId = field(default_factory=ServerId)
    client_info: ClientInfo = field(default_factory=ClientInfo)
    connect_opts: ConnectOpts = field(default_factory=ConnectOpts)
    user_nkey: str = field(default="")

    def get_user_nkey(self):
        keypair_from_pubkey(self.user_nkey.encode())

    def validate(self, vr: ValidationResults) -> None:
        pass

class AuthRequestClaims(ClaimsData):
    nats: AuthRequestData = field(default_factory=AuthRequestData)
    name: str = field(default="")

    def __post_init__(self):
        if self.sub == "":
            raise ValueError("subject is required")

    def claim_type(self) -> ClaimType:
        return AuthorizationRequestClaim


    def encode(self, pair: nkeys.KeyPair) -> str: # noqa
        """
        Raises:
            ValueError: if Decode fails
        :param pair:
        :return:
        """
        # nkeys.IsValidPublicUserKey
        Decode(nkeys.PREFIX_BYTE_USER, self.sub.encode())

        self.nats.type = AuthorizationRequestClaim
        return super().encode(pair, self)

    def validate(self, vr: ValidationResults):
        super().validate(vr)
        self.nats.validate(vr)

    def expected_prefixes(self) -> list[PrefixByte]:
        return [nkeys.PREFIX_BYTE_USER]

    def claims(self) -> ClaimsData:
        return self

    def payload(self) -> AuthRequestData:
        return self.nats
