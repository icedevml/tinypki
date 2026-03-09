import json

from jwcrypto import jwt
from sqlalchemy.exc import NoResultFound
from sqlmodel import Session, select

from ..dbmodels.tinypki import TinyJWKProvisioner
from ..internal.atrest_key import create_atrest_jwk
from ..internal.exc import NoDefaultProvisioner


def get_default_jwk_provisioner(session: Session):
    try:
        jwk_provisioner = session.exec(select(TinyJWKProvisioner).where(TinyJWKProvisioner.is_default == True)).one()
    except NoResultFound:
        raise NoDefaultProvisioner()

    key = create_atrest_jwk()
    token = jwt.JWT(algs=["A256GCMKW", "A256GCM"], check_claims={"aud": "stored-jwk-provisioner"})
    token.deserialize(jwk_provisioner.provisioner_jwe, key=key)
    claims = json.loads(token.claims)
    return claims["provisioner"]
