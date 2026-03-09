import ipaddress
import json
import re
from urllib.parse import urlparse

from cryptography import x509
from wtforms.validators import ValidationError


def validate_subject_name(_form, field):
    if not field.data:
        return

    try:
        x509.Name.from_rfc4514_string(field.data)
    except Exception as e:
        raise ValidationError("Invalid subject name: " + str(e))


def validate_subject_alt_names(_form, field):
    if not field.data:
        return

    lines = field.data.strip().splitlines()
    errors = []

    for i, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue

        if ':' not in line:
            errors.append(f"Line {i}: missing prefix (expected dns:, ip:, email:, or uri:)")
            continue

        prefix, _, value = line.partition(':')
        prefix = prefix.lower()

        if prefix == 'dns':
            if not value or not re.match(
                    r'^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$',
                    value):
                errors.append(f"Line {i}: invalid DNS name '{value}'")

        elif prefix == 'ip':
            try:
                ipaddress.ip_address(value)
            except ValueError:
                errors.append(f"Line {i}: invalid IP address '{value}'")

        elif prefix == 'email':
            if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', value):
                errors.append(f"Line {i}: invalid email address '{value}'")

        elif prefix == 'uri':
            _, _, raw_value = value.partition(':')
            parsed = urlparse(f'uri:{raw_value}' if '://' not in raw_value else raw_value)
            if not parsed.scheme or not parsed.netloc:
                errors.append(f"Line {i}: invalid URI '{raw_value}'")

        else:
            errors.append(f"Line {i}: unknown prefix '{prefix}' (expected dns:, ip:, email:, or uri:)")

    if errors:
        for err in errors:
            field.errors.append(err)


def validate_time_duration(_form, field):
    _UNIT = r'(\d+\.?\d*|\d*\.\d+)(ns|us|µs|ms|s|m|h)'
    _DURATION_RE = re.compile(
        rf'^[+-]?({_UNIT})+$'
    )

    if not field.data:
        return

    if field.data in ('0', '+0', '-0'):
        return

    if not _DURATION_RE.match(field.data):
        raise ValidationError("Invalid time duration.")


def validate_json_string(_form, field):
    if not field.data:
        return

    try:
        json.loads(field.data)
    except ValueError as e:
        raise ValidationError("Failed to parse JSON: " + str(e))
