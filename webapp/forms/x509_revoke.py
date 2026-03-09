from starlette_wtf import StarletteForm
from wtforms import StringField, HiddenField, SelectField
from wtforms.validators import AnyOf, DataRequired

from ..stepapi.revoke import RevocationReason


class X509RevokeForm(StarletteForm):
    action = StringField(validators=[AnyOf(["revoke_certificate"])])
    serial_no = HiddenField(validators=[DataRequired()])
    confirm_serial_no = StringField("", validators=[DataRequired()])
    reason = SelectField(
        'Reason',
        validators=[DataRequired()],
        choices=[(o.name, f"{o.name} ({o.value})") for o in RevocationReason]
    )
