from starlette_wtf import StarletteForm
from wtforms import StringField, HiddenField, SelectField, IntegerField
from wtforms.validators import DataRequired, AnyOf, NumberRange

from ..dbmodels.tinypki import SubjectMode, KeygenFlow
from ..internal.form_validators import validate_time_duration


class BaseBlueprintForm(StarletteForm):
    provisioner_name = SelectField('Provisioner', validators=[DataRequired()])
    invitation_validity_days = IntegerField(
        'Invitation validity (days)',
        validators=[DataRequired(), NumberRange(min=1)],
        default=7,
    )
    not_before = StringField('Cert. backdate interval',
                             validators=[DataRequired(), validate_time_duration],
                             default='-1m')
    not_after_days = IntegerField(
        'Default cert. validity (days)',
        validators=[DataRequired(), NumberRange(min=1)],
        default=730,
    )
    key_algorithm = SelectField(
        'Key algorithm',
        validators=[DataRequired()],
        choices=[]
    )
    keygen_flow = SelectField(
        'Generation flow',
        validators=[DataRequired()],
        choices=[
            ("CLIENT_SIDE", "In-browser private key generation (recommended)"),
            ("SERVER_SIDE", "Server-side private key generation (discouraged)")
        ],
        default="CLIENT_SIDE",
        coerce=KeygenFlow.coerce,
    )
    subject_mode = SelectField(
        'Subject mode',
        validators=[DataRequired()],
        choices=[
            ("DEFAULT", "Manually enter the Common Name and DNS names for each certificate"),
            ("SIMPLE_DNS", "Every certificate will contain a single DNS name"),
            ("SIMPLE_EMAIL", "Every certificate will contain a single e-mail"),
        ],
        default="SIMPLE_EMAIL",
        coerce=SubjectMode.coerce,
    )


class AddBlueprintForm(BaseBlueprintForm):
    name = StringField('Name', validators=[DataRequired()])


class EditBlueprintForm(BaseBlueprintForm):
    action = HiddenField(validators=[DataRequired(), AnyOf(["edit_blueprint"])])


class DeleteBlueprintForm(StarletteForm):
    action = HiddenField(validators=[DataRequired(), AnyOf(["delete_blueprint"])])
    name = StringField("", validators=[DataRequired()])
