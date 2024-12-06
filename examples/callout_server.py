import os
import asyncio
from dataclasses import dataclass, field
import base64
import json
import typing as t

import nats
import nkeys

from nats_jwt.v2.snippets import UserClaims, User as UserSnippet, AuthorizationResponse
from nats_jwt.v2.user_claims import User
from nats_jwt.v2.auth_claims import AuthResponseClaims, AuthResponseData, AuthRequestClaims

nseed = os.getenv("NATS_ISSUER_NSEED")

issuerKeyPair = nkeys.from_seed(nseed.encode())

user_template = {
    "permissions":{
     "pub": {
        "allow": [">"]
      },
      "sub": {
        "allow": ["x.>"]
      },
}
}

"""
This function allows every user no matter what username and what password
"""
async def calllout_handler(msg, nc):
    token = msg.data.decode()
    parsed_token = AuthRequestClaims.decode_claims(token)
    connect_opts =  parsed_token.nats.connect_opts
    account = 'APP'
    u = UserSnippet(signer_kp=issuerKeyPair, claims=UserClaims(aud=account, name=connect_opts.user, nats=User(**user_template['permissions']), sub=parsed_token.nats.user_nkey))
    user_jwt = u.jwt
    ar = AuthorizationResponse(claims=AuthResponseClaims(aud=parsed_token.nats.server_id.id ,nats=AuthResponseData(jwt=user_jwt), sub=parsed_token.nats.user_nkey, name=connect_opts.user), signer_kp=issuerKeyPair)
    jwt = ar.jwt.encode()
    await nc.publish(msg.reply,jwt)
    

async def run():
    nc = await nats.connect("nats://auth:auth@localhost:4222")
    sub = await nc.subscribe("$SYS.REQ.USER.AUTH")
    async for msg in sub.messages:
        await calllout_handler(msg, nc)

if __name__ == '__main__':
    asyncio.run(run())