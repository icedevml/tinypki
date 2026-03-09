# import uuid
# from datetime import timezone, datetime, timedelta
#
# import httpx
# import jwt
#
# from .provisioner import get_provisioner_jwk
# from .unused_admin_cert import issue_admin_cert
# from ..config import TINYPKI_STEP_CA_URL
#
# provisioner = await get_provisioner_jwk('admin', password='admin')
# admin_cert = issue_admin_cert(provisioner, 'step')
#
#
# def create_acme_provisioner(admin_cert: dict) -> dict | None:
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
#     while True:
#         payload = {
#             "type": "ACME",
#             "name": "acme",
#             "details": {
#                 "ACME": {}
#             },
#             "claims": {
#                 "x509": {"enabled": True, "durations": {}},
#                 "ssh": {"enabled": False, "userDurations": {}, "hostDurations": {}}
#             },
#             "x509Template": {},
#             "sshTemplate": {}
#         }
#
#         res = httpx.post(
#             TINYPKI_STEP_CA_URL + "/provisioners",
#             json=payload,
#             headers={"Authorization": ott},
#             verify=False)
#         res.raise_for_status()
#
#         print(res.json())
