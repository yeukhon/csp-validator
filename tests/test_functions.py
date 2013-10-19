# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import unittest
from csp_validator import csp

class TestParsePolicy(unittest.TestCase):

    def test_policy_with_just_default_src(self):
        policy = "default-src 'self';"
        d = csp.parse_policy(policy)
        self.assertEqual(['default-src'], d.keys())
        self.assertEqual(["'self'"], d['default-src'])

    def test_policy_with_default_src_ends_without_semicolon(self):
        policy = "default-src 'self'"
        d = csp.parse_policy(policy)
        self.assertEqual(['default-src'], d.keys())
        self.assertEqual(["'self'"], d['default-src'])
    
    def test_policy_with_two_directives(self):
        policy = "default-src 'self' google.com; img-src *;"
        d = csp.parse_policy(policy)
        self.assertEqual(['default-src', 'img-src'], d.keys())
        self.assertEqual(["'self'", "google.com"], d['default-src'])
        self.assertEqual(["*"], d['img-src'])

class TestValidateDirective(unittest.TestCase):
    def _test(self, name, expectation):
        r = csp.validate_directive(name)
        self.assertEqual(expectation, r)

    def test_default_src_in_directive(self):
        self._test("default-src", True)

    def test_default_src_case_insentitive_in_directive(self):
        self._test("DeFault-srC", True)

    def test_script_src_in_directive(self):
        self._test("script-src", True)

    def test_unknown_src_not_in_directive(self):
        self._test("unknown_src", False)


class TestParseSourceList(unittest.TestCase):
    def _test(self, slist, expectation):
        r = csp.parse_source_list(slist)
        self.assertEqual(expectation, r)

    def test_self_is_parsable(self):
        self._test(["'self'"], True)

    def test_self_url_is_parsable(self):
        self._test(["'self'", "google.com"], True)

    def test_none_is_parsable(self):
        self._test(["'none'"], True)

    def test_none_url_not_parsable(self):
        self._test(["'none'", "google.com"], False)

    def test_url_none_not_parsable(self):
        self._test(["google.com", "'none'"], False)


class TestMatchSourceExpressions(unittest.TestCase):
    
    def _test(self, slist, expectation):
        r = csp.match_source_expressions(slist)
        self.assertEqual(expectation, r)

    def test_slist_with_just_self(self):
        self._test(["'self'"], True)

    def test_slist_with_self_and_uri(self):
        self._test(["'self'", "google.com"], True)

    def test_slist_with_self_without_quote_should_not_fail(self):
        # CSP allows hostname like self, localhost, mail
        self._test(["self", "google.com"], True)

class TestValidate(unittest.TestCase):
    def _assert_valid(self, policy, expectation):
        r = csp.validate(policy)
        self.assertEqual(expectation, r["valid"])

    def _assert_errors(self, policy, errors=None, directive=None):
        r = csp.validate(policy)
        if not errors and directive:
            found = False
            for i, d in enumerate(r["errors"]):
                if d.get(directive):
                    found = True
            if found:
                self.assertEqual(True, r["errors"][directive] != [])
                self.assertEqual(True, directive in r["errors"][directive])
                self.assertEqual(True, "unknown directive" in r["errors"][directive])
            else:
                return False
        else:
            self.assertEqual([], r["errors"])

    def test_policy_with_just_default_src(self):
        policy = "default-src 'self';"
        d = csp.validate(policy)
        self._assert_valid(policy, True)
        self._assert_errors(policy, errors=None)

    def test_policy_with_default_src_ends_without_semicolon(self):
        policy = "default-src 'self'"
        d = csp.validate(policy)
        self._assert_valid(policy, True)
        self._assert_errors(policy, errors=None)

    def test_policy_with_two_directives(self):
        policy = "default-src 'self' google.com; img-src *;"
        d = csp.validate(policy)
        self._assert_valid(policy, True)
        self._assert_errors(policy, errors=None)

    def test_policy_with_unknown_directive(self):
        policy = "unknown-src 'self' google.com;"
        d = csp.validate(policy)
        self._assert_valid(policy, False)
        self._assert_errors(policy, directive="unknown-src")

    def test_policy_with_unkown_directive_as_second_directive(self):
        policy = "default-src 'self' google.com; unknown-src *;"
        d = csp.validate(policy)
        self._assert_valid(policy, False)
        self._assert_errors(policy, directive="uknown-src")

if __name__ == "__main__":
    unittest.main()
