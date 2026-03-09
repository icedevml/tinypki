# import uuid
# from datetime import datetime, timedelta, timezone
#
# import httpx
# import jwt
#
# from ..config import TINYPKI_STEP_CA_URL
#
#
# def list_provisioners(admin_cert: dict):
#     jwt_body = {
#         "aud": TINYPKI_STEP_CA_URL + "/admin/provisioners",
#         "exp": datetime.now(tz=timezone.utc) + timedelta(minutes=5),
#         "iat": datetime.now(tz=timezone.utc),
#         "nbf": datetime.now(tz=timezone.utc),
#         "jti": str(uuid.uuid4()),
#         "iss": admin_cert["iss"],
#         "sub": "admin"
#     }
#
#     ott = jwt.encode(
#         jwt_body,
#         key=admin_cert["key_pem"],
#         headers={
#             "x5c": admin_cert["x5c"]
#         },
#         algorithm="ES384"
#     )
#
#     res = httpx.get(TINYPKI_STEP_CA_URL + "/admin/provisioners", headers={"Authorization": ott}, verify=False)
#     return res.json()
