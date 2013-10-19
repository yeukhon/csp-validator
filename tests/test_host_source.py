# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import re
import unittest

from csp_validator import csp
from csp_validator import constant

tests_cases = [
    "http",
    "https",
    "ftp",
    "data",
    "blob",
    "http://",
    "https://",
    "ftp://",
    "data://",
    "blob://",
    "http://foobar.com",
    "http://f",
    "http://f.com",
    "http://foo.bar.com",
    "http://*.foobar.com",
    "http://*.foo",
    "foo.com",
    "*.foobar.com",
    "*",
    "a.b.c",
    "foo.*.com",
    "foo.*",
    "http://foo-bar.com",
    "http://*.foo-bar.com",
    "http://foo-bar.barfoo.com",
    "abc",
    "http://foobar.com:123",
    "http://foobar.com:*",
    "http://*.foobar.com:*",
    "http://*.foobar.com:123",
    "http://foo-bar.foo.com:*",
    "http://foobar.com:"
]

class TestHostSource(unittest.TestCase):
    def _test(self, target, expectation):
        r = csp.match(target, constant.HOST_SOURCE)
        self.assertEqual(expectation, r)

    # commented this part out because host source accepts
    # 1*host-char, so http is a valid hostname
    """
    def test_scheme_source_should_fail(self):
        cases = ["http", "https",  "ftp", "data", "blob"]
        for i, u in enumerate(cases):
            self._test(u, False)
        for i, u in enumerate(cases):
            self._test(u + ":", False)
        for i,u in enumerate(cases):
            self._test(u + "://", False)
    """

    def test_good_top_level_domains(self):
        cases = [
            "http://foobar.com",
            "foobar.com",
            "http://foo-bar.com",
            "foo-bar.com"]
        for i, u in enumerate(cases):
            self._test(u, True)

    def test_bad_top_level_domain(self):
        cases = [
            "http://fo!o.com",
            "fo!o.com",
            "fo-ba!r.com",
            "http://fo-ba!r.com"
        ]
        for i, u in enumerate(cases):
            self._test(u, False)

    def test_good_wildcard_domains(self):
        cases = [
            "http://*.foobar.com",
            "*.foobar.com",
            "*.foo-bar.com"
        ]
        for i, u in enumerate(cases):
            self._test(u, True)

    def test_bad_wildcard_domains(self):
        cases = [
            "http://foo.*.com",
            "http://foo*.com",
            "foo*.com",
            "*.foo.*.com"
        ]
        for i, u in enumerate(cases):
            self._test(u, False)

    def test_good_domains_with_port(self):
        cases = [
            "http://foo.com:123",
            "http://foo.com:*",
            "foo.com:123",
            "foo.com:*",
            "foo-bar.com:123",
            "foo-bar.com:*",
            "http://foo-bar.com:123",
            "http://foo-bar.com:*",
            "*.foo.com:123",
            "*.foo.com:*",
            "http://*.foo.com:123",
            "http://*.foo.com:*",
        ]

        for i, u in enumerate(cases):
            self._test(u, True)

    def test_bad_domains_with_ports(self):
        cases = [
            "http://foo.com:!!!",
            "http://foo.com:",
            "foo.com:",
            "foo.com:!!!",
            "*.foo.com:",
            "*.foo.com:!!!"
        ]

        for i, u in enumerate(cases):
            self._test(u, False)


"""
t = t3 = '((https|http|data|blob|javascript|ftp)\:\/\/)?((\*\.)?[a-z0-9\-]+(\.[a-z0-9\-]+)*|\*)(\:(\*|[0-9]+))?'
r = re.compile(t)
for index, t in enumerate(tests_cases):
    m = r.match(t)
    if m:
        print("target:  %s   =====>  %s" % (t, str(m.group())))
    else:
        print("target:  %s   =====>  %s" % (t, "no match!"))
"""

