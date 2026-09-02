"""Phrase → CWE rules for narrative extractors.

Order is match order (first listed still wins for *insertion* after dedupe).
Edit this table, not a regex pile in artifacts.py. owner=narrative unless a
scanner adapter teaches a phrase.
"""

from __future__ import annotations

import re

FAMILIES = (
    "injection", "request", "traversal", "upload", "auth", "integrity",
    "crypto", "xml", "memory", "dos", "regex", "info", "deserial", "race",
    "path", "session", "other",
)

PHRASE_CWE_RULES: list[dict] = [
    {"id": 'ssti', "family": 'injection', "cwe": 'CWE-1336', "pattern": 'server[- ]side template injection|\\bsti\\b', "owner": 'narrative', "note": 'before rce (CWE-94); SSTI phrase must not become CWE-94'},
    {"id": 'sqli', "family": 'injection', "cwe": 'CWE-89', "pattern": 'sql\\s*injection|\\bsqli\\b|arbitrary SQL|execute arbitrary SQL', "owner": 'narrative'},
    {"id": 'xss', "family": 'injection', "cwe": 'CWE-79', "pattern": 'cross[- ]site scripting|\\bxss\\b|save javascript|javascript is executed|javascript execution|execute arbitrary JavaScript|HTML injection|inject scripts or HTML', "owner": 'narrative'},
    {"id": 'csrf', "family": 'request', "cwe": 'CWE-352', "pattern": 'cross[- ]site request forgery|\\bcsrf\\b', "owner": 'narrative'},
    {"id": 'ssrf', "family": 'request', "cwe": 'CWE-918', "pattern": 'server[- ]side request forgery|\\bssrf\\b', "owner": 'narrative'},
    {"id": 'path-restriction', "family": 'traversal', "cwe": 'CWE-24', "pattern": 'escape the directory|path restriction', "owner": 'narrative'},
    {"id": 'path-traversal', "family": 'traversal', "cwe": 'CWE-22', "pattern": 'path traversal|directory traversal', "owner": 'narrative'},
    {"id": 'unrestricted-upload', "family": 'upload', "cwe": 'CWE-434', "pattern": 'unrestricted (?:file )?upload|arbitrary file upload', "owner": 'narrative'},
    {"id": 'crlf', "family": 'request', "cwe": 'CWE-93', "pattern": 'header injection|\\bcrlf\\b|CR\\s*&\\s*LF|CRLF|CR\\s+and\\s+LF', "owner": 'narrative'},
    {"id": 'idor', "family": 'auth', "cwe": 'CWE-639', "pattern": 'insecure direct object|\\bidor\\b', "owner": 'narrative'},
    {"id": 'authz-bypass', "family": 'auth', "cwe": 'CWE-863', "pattern": 'authorization bypass|missing permission checks|incorrect permission', "owner": 'narrative'},
    {"id": 'open-redirect', "family": 'request', "cwe": 'CWE-601', "pattern": 'open redirect', "owner": 'narrative'},
    {"id": 'missing-authz', "family": 'auth', "cwe": 'CWE-862', "pattern": 'missing authorization|unable to edit or delete', "owner": 'narrative'},
    {"id": 'missing-authn', "family": 'auth', "cwe": 'CWE-306', "pattern": 'missing authentication|no authentication|without any authentication|unauthenticated attacker|exploitable without any authentication', "owner": 'narrative'},
    {"id": 'integrity-untracked', "family": 'integrity', "cwe": 'CWE-353', "pattern": 'not tracked by|integrity check', "owner": 'narrative'},
    {"id": 'weak-crypto', "family": 'crypto', "cwe": 'CWE-327', "pattern": 'weakening the subsequent encryption|weaken(?:s|ed|ing)? .{0,40}encryption', "owner": 'narrative'},
    {"id": 'weak-iv', "family": 'crypto', "cwe": 'CWE-330', "pattern": 'initialization vector|returned the initial IV', "owner": 'narrative'},
    {"id": 'xxe', "family": 'xml', "cwe": 'CWE-611', "pattern": 'xml external entity|\\bxxe\\b|improper parsing of XML', "owner": 'narrative'},
    {"id": 'escape-sequences', "family": 'injection', "cwe": 'CWE-150', "pattern": 'control characters|escape sequences|ANSI escape', "owner": 'narrative'},
    {"id": 'os-command', "family": 'injection', "cwe": 'CWE-78', "pattern": 'os command', "owner": 'narrative', "exclusive_with": ['command-injection'], "note": 'os command → 78; command injection wording → 77'},
    {"id": 'command-injection', "family": 'injection', "cwe": 'CWE-77', "pattern": 'command injection|execute arbitrary command|arbitrary command', "owner": 'narrative', "exclusive_with": ['os-command']},
    {"id": 'heap-overflow', "family": 'memory', "cwe": 'CWE-122', "pattern": 'heap[- ]based buffer overflow|heap[- ]buffer[- ]overflow', "owner": 'narrative'},
    {"id": 'stack-overflow', "family": 'memory', "cwe": 'CWE-121', "pattern": 'stack[- ]based buffer overflow|stack overflow|allocation on the stack', "owner": 'narrative'},
    {"id": 'buffer-overflow', "family": 'memory', "cwe": 'CWE-119', "pattern": 'buffer overflow|overflow the .{0,120}protocol|\\boverflow the\\b', "owner": 'narrative'},
    {"id": 'oob-write', "family": 'memory', "cwe": 'CWE-787', "pattern": 'out[- ]of[- ]bounds write|out of bounds write|out[- ]of[- ]bounds memory write', "owner": 'narrative'},
    {"id": 'oob-read', "family": 'memory', "cwe": 'CWE-125', "pattern": 'out[- ]of[- ]bounds read|out of bounds read|out[- ]of[- ]bounds heap read|\\boob read\\b|without valid bounds checking', "owner": 'narrative'},
    {"id": 'uaf', "family": 'memory', "cwe": 'CWE-416', "pattern": 'use[- ]after[- ]free', "owner": 'narrative'},
    {"id": 'int-overflow', "family": 'memory', "cwe": 'CWE-190', "pattern": 'integer overflow|integer wraparound|overflows and underflows', "owner": 'narrative'},
    {"id": 'int-underflow', "family": 'memory', "cwe": 'CWE-191', "pattern": 'integer underflow|\\bunderflows\\b', "owner": 'narrative'},
    {"id": 'null-deref', "family": 'memory', "cwe": 'CWE-476', "pattern": 'null pointer|null dereference', "owner": 'narrative'},
    {"id": 'mem-leak', "family": 'memory', "cwe": 'CWE-401', "pattern": 'memory leak|never freed|without freeing|leaks approximately', "owner": 'narrative'},
    {"id": 'infinite-loop', "family": 'dos', "cwe": 'CWE-835', "pattern": 'infinite loop', "owner": 'narrative'},
    {"id": 'redos', "family": 'regex', "cwe": 'CWE-1333', "pattern": 'regular expression denial of service|\\bredos\\b|inefficient regular expression|regular expression (?:complexity|exponential blowup)', "owner": 'narrative'},
    {"id": 'undefined-behavior', "family": 'memory', "cwe": 'CWE-758', "pattern": 'undefined behavior', "owner": 'narrative'},
    {"id": 'improper-access-control', "family": 'auth', "cwe": 'CWE-284', "pattern": 'improper access control', "owner": 'narrative'},
    {"id": 'unauthorized-access', "family": 'auth', "cwe": 'CWE-287', "pattern": 'unauthorized access', "owner": 'narrative'},
    {"id": 'authn-bypass', "family": 'auth', "cwe": 'CWE-288', "pattern": 'authentication bypass|bypass administrator authentication|bypass authentication', "owner": 'narrative'},
    {"id": 'double-free', "family": 'memory', "cwe": 'CWE-415', "pattern": 'double free', "owner": 'narrative'},
    {"id": 'format-string', "family": 'memory', "cwe": 'CWE-134', "pattern": 'format string', "owner": 'narrative'},
    {"id": 'prototype-pollution', "family": 'injection', "cwe": 'CWE-1321', "pattern": 'prototype pollution', "owner": 'narrative'},
    {"id": 'info-leak', "family": 'info', "cwe": 'CWE-200', "pattern": 'information disclosure|information leak|leak sensitive information|obtain sensitive information|obtain information about|exposure of sensitive information|local file read|\\blfr\\b|full names of other users|enumerate the user names', "owner": 'narrative'},
    {"id": 'insecure-deser', "family": 'deserial', "cwe": 'CWE-502', "pattern": 'insecure deseriali[sz]ation|unsafe java deseriali[sz]ation|deseriali[sz](?:e|ation|ing) of untrusted|deserializ(?:e|ing) untrusted|pickle deseriali[sz]ation|malicious pickle', "owner": 'narrative'},
    {"id": 'race', "family": 'race', "cwe": 'CWE-362', "pattern": 'race condition', "owner": 'narrative'},
    {"id": 'div-zero', "family": 'memory', "cwe": 'CWE-369', "pattern": 'divide by zero|division by zero', "owner": 'narrative'},
    {"id": 'type-confusion', "family": 'memory', "cwe": 'CWE-843', "pattern": 'type confusion', "owner": 'narrative'},
    {"id": 'off-by-one', "family": 'memory', "cwe": 'CWE-193', "pattern": 'off[- ]by[- ]one', "owner": 'narrative'},
    {"id": 'uninitialized', "family": 'memory', "cwe": 'CWE-457', "pattern": 'uninitialized', "owner": 'narrative'},
    {"id": 'origin-validation', "family": 'auth', "cwe": 'CWE-346', "pattern": 'same.origin|origin validation', "owner": 'narrative'},
    {"id": 'cleartext', "family": 'crypto', "cwe": 'CWE-319', "pattern": 'clear[- ]?text(?: credentials)?|credentials in clear text|plaintext (?:password|transmission)|transmitted in plaintext|unencrypted (?:channel|traffic|\\)|\\s)|unsecured \\(unencrypted\\)', "owner": 'narrative'},
    {"id": 'weak-base64', "family": 'crypto', "cwe": 'CWE-261', "pattern": 'sent in base64|reversible base64|base64(?:url)?(?: encoding)?.{0,40}(?:credential|password|cipher)|not considered a strong cipher', "owner": 'narrative'},
    {"id": 'forced-browsing', "family": 'auth', "cwe": 'CWE-425', "pattern": 'forced browsing|directly request', "owner": 'narrative'},
    {"id": 'priv-esc', "family": 'auth', "cwe": 'CWE-269', "pattern": 'sudoers|privilege escalation|escalate privileges', "owner": 'narrative'},
    {"id": 'idor-predictable-key', "family": 'auth', "cwe": 'CWE-639', "pattern": 'authorization bypass through user[- ]controlled key|iterate through predictable values|predictable values of', "owner": 'narrative', "note": 'user-controlled key / predictable values'},
    {"id": 'file-inclusion', "family": 'injection', "cwe": 'CWE-98', "pattern": 'php remote file inclusion|local file inclusion|\\blfi\\b|\\brfi\\b', "owner": 'narrative'},
    {"id": 'rce', "family": 'injection', "cwe": 'CWE-94', "pattern": 'code injection|remote c[oa]de execution|\\brce\\b|execute malicious code', "owner": 'narrative'},
    {"id": 'improper-escaping', "family": 'injection', "cwe": 'CWE-116', "pattern": 'improper encoding or escaping', "owner": 'narrative'},
    {"id": 'mass-assignment', "family": 'auth', "cwe": 'CWE-915', "pattern": 'mass assignment', "owner": 'narrative'},
    {"id": 'ldap-injection', "family": 'injection', "cwe": 'CWE-90', "pattern": 'ldap injection', "owner": 'narrative'},
    {"id": 'decompression-bomb', "family": 'dos', "cwe": 'CWE-409', "pattern": 'decompression bombs?', "owner": 'narrative'},
    {"id": 'dll-search', "family": 'path', "cwe": 'CWE-427', "pattern": 'dll search path', "owner": 'narrative'},
    {"id": 'cswsh', "family": 'request', "cwe": 'CWE-1385', "pattern": 'cross[- ]site websocket hijacking|\\bcswsh\\b|accept connections from any origin|origin header validation|origin header', "owner": 'narrative'},
    {"id": 'missing-httponly', "family": 'session', "cwe": 'CWE-1004', "pattern": 'missing httponly|httponly flag', "owner": 'narrative'},
    {"id": 'session-fixation', "family": 'session', "cwe": 'CWE-384', "pattern": 'hijack an authenticated session|credentials as the session id', "owner": 'narrative'},
    {"id": 'brute-force', "family": 'auth', "cwe": 'CWE-307', "pattern": 'brute[- ]force|without triggering lockout|unlimited password[- ]change', "owner": 'narrative'},
    {"id": 'windows-device-names', "family": 'path', "cwe": 'CWE-67', "pattern": 'windows device names', "owner": 'narrative'},
    {"id": 'reduced-entropy', "family": 'crypto', "cwe": 'CWE-331', "pattern": 'reduced entropy|bits of randomness', "owner": 'narrative'},
    {"id": 'never-released', "family": 'dos', "cwe": 'CWE-772', "pattern": 'never released', "owner": 'narrative'},
    {"id": 'long-runtimes', "family": 'dos', "cwe": 'CWE-400', "pattern": 'long runtimes', "owner": 'narrative'},
    {"id": 'ssrf-loopback', "family": 'request', "cwe": 'CWE-918', "pattern": 'requests against loopback|requests to local ip', "owner": 'narrative', "note": 'loopback/local-ip SSRF phrasing'},
    {"id": 'out-of-memory', "family": 'dos', "cwe": 'CWE-400', "pattern": 'out of memory', "owner": 'narrative'},
    {"id": 'unbounded-alloc', "family": 'dos', "cwe": 'CWE-400', "pattern": 'unbounded (?:heap|memory)(?: allocation)?|unbounded (?:heap |memory )?allocation|denial[- ]of[- ]service|heap exhaustion|OutOfMemoryError', "owner": 'narrative'},
    {"id": 'unbounded-heap', "family": 'dos', "cwe": 'CWE-789', "pattern": 'unbounded heap allocation|allocate a byte array of the declared length', "owner": 'narrative'},
    {"id": 'user-enum', "family": 'info', "cwe": 'CWE-204', "pattern": 'username enumeration|user enumeration', "owner": 'narrative'},
    {"id": 'distinct-errors', "family": 'info', "cwe": 'CWE-203', "pattern": 'different error messages depending', "owner": 'narrative'},
    {"id": 'improper-authz', "family": 'auth', "cwe": 'CWE-285', "pattern": 'improper authorization', "owner": 'narrative'},
    {"id": 'improper-authentication', "family": 'auth', "cwe": 'CWE-287', "pattern": 'improper authentication', "owner": 'narrative'},
    {"id": 'weak-password-check', "family": 'auth', "cwe": 'CWE-287', "pattern": 'skip email 2fa|incorrectly validate the password|provides any password', "owner": 'narrative'},
    {"id": 'timing-side-channel', "family": 'crypto', "cwe": 'CWE-208', "pattern": 'timing side[- ]channel', "owner": 'narrative'},
]


def compiled_bug_cwe() -> tuple[tuple[re.Pattern[str], str], ...]:
    return tuple((re.compile(r["pattern"], re.I), r["cwe"]) for r in PHRASE_CWE_RULES)


TAUGHT_CWE = frozenset(r["cwe"] for r in PHRASE_CWE_RULES)

