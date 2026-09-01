from vulnavigator.pipeline import analyze_text


SQLI = (
    "A security flaw has been discovered in itsourcecode School Management System 1.0. "
    "This affects an unknown part of the file /student/index.php. "
    "The manipulation of the argument ID results in sql injection. "
    "It is possible to launch the attack remotely. "
    "The exploit has been released to the public and may be used for attacks."
)

SSTI = (
    "Bagisto is an open source laravel eCommerce platform. Versions prior to 2.3.10 "
    "are vulnerable to server-side template injection. When a normal customer orders "
    "any product, in the add address step they can inject a value."
)


def test_blind_nvd_sqli_is_not_ai_zeroday():
    case = analyze_text(SQLI, offline=True)[0]
    assert "CVE-" not in case.title or case.cves == []
    assert case.cves == []
    assert case.source_kind == "narrative"
    assert "CWE-89" in case.cwes
    assert case.asset_internet_facing is True
    assert any(loc.path.endswith("index.php") for loc in case.locations)
    assert "School Management System" in (case.product or "")
    assert case.version == "1.0"
    assert "public exploit" in case.evidence.notes.lower()
    assert any(m.id.split(".")[0] == "T1190" for m in case.attack)
    assert not any("No CVE expected" in n for n in case.validation_notes)
    assert not any("AI 0-day identity" in n for n in case.validation_notes)


def test_buffer_overflow_and_uaf():
    text = (
        "iccDEV provides libraries for ICC profiles. Versions 2.3.1 and below contain "
        "Use After Free, Heap-based Buffer Overflow and Integer Overflow vulnerabilities."
    )
    case = analyze_text(text, offline=True)[0]
    assert "CWE-416" in case.cwes
    assert "CWE-122" in case.cwes
    assert "CWE-190" in case.cwes
    assert case.product.lower() == "iccdev"


def test_wordpress_plugin_path_traversal_is_remote():
    text = (
        "The FastDup plugin for WordPress is vulnerable to Path Traversal in all "
        "versions up to, and including, 2.7 via the dir_path parameter in a REST API endpoint."
    )
    case = analyze_text(text, offline=True)[0]
    assert "CWE-22" in case.cwes
    assert case.asset_internet_facing is True
    assert "FastDup" in (case.product or "")


def test_header_crlf_and_ssrf_both_map():
    text = (
        "cpp-httplib is a C++11 HTTP library. Prior to version 0.30.0, write_headers "
        "does not check for CR & LF characters in user supplied headers. This can be "
        "used for server side request forgery (SSRF)."
    )
    case = analyze_text(text, offline=True)[0]
    assert "CWE-93" in case.cwes
    assert "CWE-918" in case.cwes
    assert case.product.lower() == "cpp-httplib"
    assert case.asset_internet_facing is True


def test_from_remote_sets_exposure():
    text = (
        "A vulnerability was detected in code-projects Content Management System 1.0. "
        "The file /pages.php argument ID results in sql injection. "
        "The attack may be performed from remote."
    )
    case = analyze_text(text, offline=True)[0]
    assert case.asset_internet_facing is True
    assert "CWE-89" in case.cwes


def test_model_file_is_not_ai_zeroday():
    from vulnavigator.models import is_ai_zeroday

    text = (
        "MessagePack for Java is a serializer. Versions prior to 0.9.11 allocate "
        "unbounded heap when deserializing EXT32 objects. Triggered during model "
        "loading. Can be exploited remotely. The model file is loaded from a registry."
    )
    case = analyze_text(text, offline=True)[0]
    assert not is_ai_zeroday(case)
    assert "CWE-400" in case.cwes
    assert case.asset_internet_facing is True


def test_arbitrary_sql_and_saved_javascript():
    sql = (
        "Ghost is a Node.js CMS. Users with Admin API credentials can execute "
        "arbitrary SQL on /ghost/api/admin/members/events."
    )
    case = analyze_text(sql, offline=True)[0]
    assert "CWE-89" in case.cwes
    js = (
        "OPEXUS eCASE Audit allows an authenticated attacker to save JavaScript "
        "as a comment. The JavaScript is executed whenever another user views the log."
    )
    case = analyze_text(js, offline=True)[0]
    assert "CWE-79" in case.cwes


def test_command_injection_is_cwe_77():
    text = (
        "Tenda AC1206 15.03.06.23 formBehaviorManager in /goform/BehaviorManager "
        "can lead to command injection. The attack can be launched remotely."
    )
    case = analyze_text(text, offline=True)[0]
    assert "CWE-77" in case.cwes
    assert "CWE-78" not in case.cwes


def test_libtpms_flaw_in_versions():
    text = (
        "libtpms, a library that provides software emulation of a Trusted Platform "
        "Module, has a flaw in versions 0.10.0 and 0.10.1. The integration with "
        "OpenSSL 3.x returned the initial IV, thus weakening the subsequent encryption."
    )
    case = analyze_text(text, offline=True)[0]
    assert case.product.lower() == "libtpms"
    assert case.version.startswith("0.10")
    assert "CWE-327" in case.cwes
    assert "CWE-330" in case.cwes


def test_emlog_is_an_open_source_product():
    text = (
        "Emlog is an open source website building system. In version 2.5.23, article "
        "creation is vulnerable to cross-site request forgery (CSRF)."
    )
    case = analyze_text(text, offline=True)[0]
    assert case.product.lower() == "emlog"
    assert case.version == "2.5.23"
    assert "CWE-352" in case.cwes


def test_blind_ssti_prefers_cwe_1336_over_94():
    case = analyze_text(SSTI, offline=True)[0]
    assert "CWE-1336" in case.cwes
    assert "CWE-94" not in case.cwes
    assert case.product == "Bagisto"
    assert case.version == "2.3.10"


def test_auth_bypass_stack_heap_and_xml():
    bypass = analyze_text(
        "Authentication bypass issue exists in OpenBlocks series versions prior to FW5.0.8, "
        "which may allow an attacker to bypass administrator authentication and change the password.",
        offline=True,
    )[0]
    assert "CWE-288" in bypass.cwes
    assert "OpenBlocks" in (bypass.product or "")

    stack = analyze_text(
        "iccDEV provides libraries for ICC profiles. Prior to version 2.3.1.2, iccDEV is "
        "vulnerable to stack overflow in the XML calculator macro expansion.",
        offline=True,
    )[0]
    assert "CWE-121" in stack.cwes

    heap = analyze_text(
        "iccDEV provides libraries for ICC profiles. Prior to version 2.3.1.2, iccDEV is "
        "vulnerable to heap-buffer-overflow in IccTagXml().",
        offline=True,
    )[0]
    assert "CWE-122" in heap.cwes

    xml = analyze_text(
        "A vulnerability in Cisco ISE is due to improper parsing of XML that is processed "
        "by the web-based management interface.",
        offline=True,
    )[0]
    assert "CWE-611" in xml.cwes


def test_cleartext_sudoers_redos_undefined_and_products():
    leak = analyze_text(
        "An unauthenticated, remote attacker can cause the engine to leak sensitive information.",
        offline=True,
    )[0]
    assert "CWE-200" in leak.cwes

    sudoers = analyze_text(
        "The absence of permissions control for the user XXX allows the current configuration "
        "in the sudoers file to escalate privileges without any restrictions.",
        offline=True,
    )[0]
    assert "CWE-269" in sudoers.cwes

    regex = analyze_text(
        "Inefficient Regular Expression Complexity vulnerability in MediaWiki - VisualData "
        "Extension allows Regular Expression Exponential Blowup. This issue affects "
        "MediaWiki - VisualData Extension: 1.45.",
        offline=True,
    )[0]
    assert "CWE-1333" in regex.cwes
    assert "VisualData" in (regex.product or "")

    undef = analyze_text(
        "iccDEV provides ICC profile libraries. Versions 2.3.1 and below have Undefined Behavior "
        "in CIccCLUT::Init.",
        offline=True,
    )[0]
    assert "CWE-758" in undef.cwes

    ev = analyze_text(
        "An Improper Access Control could allow a malicious actor in Wi-Fi range to the "
        "EV Station Lite (v1.5.2 and earlier) to use WiFi AutoLink.",
        offline=True,
    )[0]
    assert "EV Station Lite" in (ev.product or "")
    assert ev.version == "1.5.2"

    clear = analyze_text(
        "An attacker with a network connection could detect credentials in clear text.",
        offline=True,
    )[0]
    assert "CWE-319" in clear.cwes

    b64 = analyze_text(
        "The credentials required to access the device's web server are sent in base64 "
        "within the HTTP headers. Since base64 is not considered a strong cipher, an "
        "attacker could obtain the credentials.",
        offline=True,
    )[0]
    assert "CWE-261" in b64.cwes
