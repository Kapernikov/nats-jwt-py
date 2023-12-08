import base64
import json
from dataclasses import dataclass

from jwt.v2.version import LIB_VERSION
from jwt.v2.account_claims import AccountClaims
from jwt.v2.claims import AccountClaim, ActivationClaim, AuthorizationRequestClaim, AuthorizationResponseClaim, \
    Claims, ClaimsData, ClaimType, \
    GenericFields, OperatorClaim, \
    PrefixByte, safe_url_base64_decode, UserClaim
from jwt.v2.header import parse_headers
from jwt.v2.operator_claims import OperatorClaims
from jwt.v2.user_claims import UserClaims


@dataclass
class _Identifier:
    type: ClaimType = ""
    nats: GenericFields = None

    def kind(self) -> ClaimType:
        return self.type or self.nats.type

    def version(self) -> int:
        return 1 if self.type else self.nats.version


def load_claims(data: bytearray | bytes | str) -> tuple[int, Claims]:
    loads = json.loads(data)
    nats = loads.get("nats", {})
    _id = _Identifier(
        type=loads.get("type"),
        nats=GenericFields(
            type=nats.get("type"),
            version=nats.get("version")
        )
    )

    if _id.version() > LIB_VERSION:
        raise ValueError(f"JWT was generated by a newer version - {_id.version()}")

    def error(claims: str):
        raise ValueError(f"{claims} are not supported")

    return _id.version(), {
        # TODO: add all claims
        # Note: claims using `classmethod`, it refers to same function, but it receives different
        # class as first argument
        OperatorClaim: OperatorClaims.load,
        AccountClaim: AccountClaims.load,
        UserClaim: UserClaims.load,
        ActivationClaim: lambda x, y: ...,
        AuthorizationRequestClaim: lambda x, y: ...,
        AuthorizationResponseClaim: lambda x, y: ...,
        "cluster": lambda x, y: error("ClusterClaims"),
        "server": lambda x, y: error("ServerClaims"),
    }.get(
        # key
        _id.kind(),
        # default
        lambda _, __: ClaimsData(**loads)
    )(loads, _id.version())


def decode(token: str) -> Claims:
    """ Decode takes a JWT string decodes it and validates it
    and return the embedded Claims. If the token header
    doesn't match the expected algorithm, or the claim is
    not valid or verification fails an error is returned

    Raises:
        ValueError:
        TypeError: initializer problem (extra arguments, missing arguments, etc.)
    """
    chunks = token.split(".")
    if len(chunks) != 3:
        raise ValueError("expected 3 chunks")

    chunks[0] = safe_url_base64_decode(chunks[0].encode()).decode()
    chunks[1] = safe_url_base64_decode(chunks[1].encode()).decode()

    parse_headers(chunks[0])  # throws TypeError, ValueError

    data = chunks[1].encode()
    version, claim = load_claims(data)  # throws TypeError, ValueError, binascii.Error

    # padding
    _sig = chunks[2] + "=" * (-len(chunks[2]) % 4)
    sig = safe_url_base64_decode(_sig.encode())  # throws binascii.Error

    if version <= 1 and not claim.verify(chunks[1].encode(), sig):
        raise ValueError("claim failed V1 signature verification")
    elif claim.verify(token[:len(chunks[0]) + len(chunks[1]) + 1].encode(), sig):
        raise ValueError("claim failed V2 signature verification")

    prefixes: list[PrefixByte] = claim.expected_prefixes()

    if prefixes:
        ...  # TODO: create validation for prefixes

    return claim
