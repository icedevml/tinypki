from enum import Enum

from fastapi import Request
from starlette.responses import JSONResponse

from ..dependencies import templates


class TinyPKIErrorReason(Enum):
    OBJECT_NOT_FOUND = "Object not found."
    REDEEM_CODE_EXPIRED = "Incorrect or expired redeem code."
    NO_SUCH_JWK_PROVISIONER = "Failed to find the designated JWK provisioner to perform the task."
    CERT_ISSUANCE_ERROR = "Failed to issue certificate due to a runtime error. Please contact administrator."
    NO_DEFAULT_PROVISIONER = "This feature requires a default JWK provisioner to be registered."
    REVOKE_NO_CERT_FOUND = "The certificate to be revoked was not found."
    REVOKE_ALREADY_REVOKED = "The certificate is already revoked."
    REVOKE_REQ_STALLED = "The certificate revocation was successfully requested, although we didn't index it within the subsequent >10 seconds. This might be a bug."
    REVOKE_GENERIC_ERR = "Generic error when trying to revoke."
    REVOKE_MISMATCHED_SERIAL = "Mismatched serial_no between the path parameter and POST data."
    INVITATION_ALREADY_CREATED = "The requested invitation was already created."
    PROVISIONER_FAILED_LOGIN = "Failed to obtain JWK provisioner using the provided details."
    PROVISIONER_ALREADY_EXISTS = "This provisioner is already registered."
    INDEXER_UNHEALTHY = "Indexer service is not healthy. Refusing access to the TinyPKI because it may had ran into a desync state with Step CA."
    NO_BLUEPRINTS_DEFINED = "This feature requires at least one blueprint to be defined."
    UNABLE_TO_DELETE_RESOURCE_HAS_DEPENDENCIES = "Unable to delete. Other resources depend on that resource."
    CLIENT_CERT_INVALID = "Failed to verify the presented client certificate. The certificate is incorrectly signed, has invalid path or was revoked."
    UNACCEPTABLE_CERT_DURATION = "The specified certificate validity duration is unacceptable by the selected JWK provisioner's policy."


class NoCertificateToRevoke(RuntimeError):
    pass


class NoDefaultProvisioner(RuntimeError):
    pass


class RevokeReqStalledError(RuntimeError):
    pass


class ProvisionerNotFound(RuntimeError):
    pass


class InvalidCSR(RuntimeError):
    pass


class TinyPKIError(RuntimeError):
    template = "error.html"
    admin_template = "admin_error.html"

    def __init__(self, status_code: int, reason: TinyPKIErrorReason):
        super().__init__(reason.value)
        self.status_code = status_code
        self.message = reason.value
        self.reason = reason

    def serialize(self, request: Request):
        if request.state.render_html_exceptions:
            if request.state.display_admin_ui:
                template = self.admin_template
            else:
                template = self.template

            return templates.TemplateResponse(template, {
                "request": request,
                "message": f"[{self.reason.name}]: {self.message}"
            })
        else:
            return JSONResponse({
                "error": {
                    "code": self.reason.name,
                    "message": self.message
                }
            }, status_code=self.status_code)
