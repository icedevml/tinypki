# import base64
#
# from cryptography.hazmat.primitives import serialization
#
# from .sign import CSR, sign_cert
#
#
# def issue_admin_cert(provisioner: dict, admin_subject: str):
#     csr = CSR(admin_subject, [admin_subject])
#     signed_data = sign_cert(provisioner, csr, "-1h", "24h", {})
#
#     x5c = [base64.b64encode(x.public_bytes(serialization.Encoding.DER)).decode('ascii') for x in signed_data["chain"]]
#     key_pem = csr.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
#                                     serialization.NoEncryption()).decode("utf-8")
#
#     return {
#         "iss": provisioner["name"],
#         "x5c": x5c,
#         "key_pem": key_pem
#     }
