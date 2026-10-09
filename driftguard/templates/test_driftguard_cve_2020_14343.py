# Added by DriftGuard for {{change_id}} ({{cve}})
# Source: {{source_url}}
# Inert regression test: partner uploads are untrusted, so Python-specific YAML tags must be rejected.
# Uses a harmless !!python/tuple tag - no code-execution payload.
import pytest
import yaml

from service.import_config import parse_partner_batch, parse_partner_config

PYTHON_TAG_DOC = "source: s3://x\nschedule: '* * * * *'\nextra: !!python/tuple [1, 2]\n"


def test_untrusted_config_rejects_python_tags():
    with pytest.raises(yaml.YAMLError):
        parse_partner_config(PYTHON_TAG_DOC)


def test_untrusted_batch_rejects_python_tags():
    with pytest.raises(yaml.YAMLError):
        parse_partner_batch(PYTHON_TAG_DOC)


def test_installed_pyyaml_outside_affected_range():
    major, minor = (int(x) for x in yaml.__version__.split(".")[:2])
    assert (major, minor) >= (5, 4), f"PyYAML {yaml.__version__} is in the affected range (< 5.4)"
