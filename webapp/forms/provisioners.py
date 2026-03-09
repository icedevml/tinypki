from starlette_wtf import StarletteForm
from wtforms import StringField, PasswordField, HiddenField, BooleanField
from wtforms.validators import DataRequired, AnyOf


class AddProvisionerForm(StarletteForm):
    name = StringField('Name', validators=[DataRequired()])
    password = PasswordField('JWK Password', validators=[DataRequired()])
    make_default = BooleanField('Mark as default')


class DeleteProvisionerForm(StarletteForm):
    action = HiddenField(validators=[DataRequired(), AnyOf(["delete_provisioner"])])
    name = StringField("", validators=[DataRequired()])
