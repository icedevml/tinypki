from starlette_wtf import StarletteForm
from wtforms import StringField, TextAreaField, HiddenField
from wtforms.fields.numeric import IntegerField
from wtforms.validators import DataRequired, AnyOf, NumberRange

from ..internal.form_validators import validate_subject_alt_names


class BaseAddInvitationForm(StarletteForm):
    submit_nonce = HiddenField(validators=[DataRequired()])
    blueprint_name = HiddenField(validators=[DataRequired()])

    invitation_validity_days = IntegerField("Invitation validity (days)",
                                            validators=[DataRequired(), NumberRange(min=1)])
    not_after_days = IntegerField("Cert. validity (days)",
                                  validators=[DataRequired(), NumberRange(min=1)])

    def assemble_subject_cn(self):
        raise NotImplemented("BaseAddInvitationForm is abstract.")

    def assemble_sans(self):
        raise NotImplemented("BaseAddInvitationForm is abstract.")


class SimpleDNSSANAddInvitationForm(BaseAddInvitationForm):
    subject_name = StringField(
        'Subject Name',
        validators=[DataRequired()],
        render_kw={'placeholder': 'example.com'}
    )

    def assemble_subject_cn(self):
        return self.subject_name.data

    def assemble_sans(self):
        return [f"dns:{self.subject_name.data}"]


class SimpleEmailSANAddInvitationForm(BaseAddInvitationForm):
    subject_name = StringField(
        'Subject Name',
        validators=[DataRequired()],
        render_kw={'placeholder': 'janusz@example.com'}
    )

    def assemble_subject_cn(self):
        return self.subject_name.data

    def assemble_sans(self):
        return [f"email:{self.subject_name.data}"]


class DefaultAddInvitationForm(BaseAddInvitationForm):
    subject_common_name = StringField(
        'Subject Common Name (CN)',
        validators=[DataRequired()],
        render_kw={'placeholder': 'example.com'}
    )
    subject_alt_names = TextAreaField(
        'Subject alternative names (one per line)',
        validators=[DataRequired(), validate_subject_alt_names],
        render_kw={'placeholder': 'Accepted values:\n'
                                  '  dns:example.com\n'
                                  '  ip:127.0.0.1\n'
                                  '  email:janusz@example.com\n'
                                  '  uri:https://example.com'}
    )

    def assemble_subject_cn(self):
        return self.subject_common_name.data

    def assemble_sans(self):
        return [v.strip() for v in self.subject_alt_names.data.split("\n") if v.strip()]


class DeleteInvitationForm(StarletteForm):
    action = HiddenField(validators=[DataRequired(), AnyOf(["delete_invitation"])])
    name = StringField("", validators=[DataRequired()])
