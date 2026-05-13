from starlette_wtf import StarletteForm
from wtforms import StringField, HiddenField
from wtforms.validators import DataRequired, AnyOf, Length


class RedeemInvitationForm(StarletteForm):
    redeem_code = StringField(
        'Redeem code',
        validators=[DataRequired(), Length(min=24, max=24)],
    )


class RedeemStep2Form(StarletteForm):
    action = HiddenField(validators=[DataRequired(), AnyOf(["redeem_code_step2"])])
    state_jwe = HiddenField(validators=[DataRequired()])
