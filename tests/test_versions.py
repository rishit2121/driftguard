from driftguard import versions

OSV_LODASH = {"affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
                            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.12"}]}]}]}
OSV_LOG4J = {"affected": [{"package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
                           "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.13.0"}, {"fixed": "2.15.0"}]}]}]}


def test_semver_range():
    assert versions.osv_affects(OSV_LODASH, "npm", "lodash", "4.17.11")[0]
    assert not versions.osv_affects(OSV_LODASH, "npm", "lodash", "4.17.12")[0]
    assert not versions.osv_affects(OSV_LODASH, "npm", "lodash", "4.18.1")[0]


def test_maven_ordering():
    assert versions.compare("Maven", "2.0-beta9", "2.0") < 0
    assert versions.compare("Maven", "2.0", "2.0.0") == 0
    assert versions.compare("Maven", "2.12.2", "2.3.1") > 0
    assert versions.osv_affects(OSV_LOG4J, "Maven", "org.apache.logging.log4j:log4j-core", "2.14.1")[0]
    assert not versions.osv_affects(OSV_LOG4J, "Maven", "org.apache.logging.log4j:log4j-core", "2.15.0")[0]


def test_pypi_and_stripe_versions():
    assert versions.compare("PyPI", "5.3.1", "5.4") < 0
    assert versions.stripe_version_at_least("2025-03-31.basil", "2025-03-31.basil")
    assert not versions.stripe_version_at_least("2024-12-18.acacia", "2025-03-31.basil")
