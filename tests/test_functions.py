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

    def _test(self, name, expectation, deprecated=False):
        valid, reason = csp.validate_directive(name)
        self.assertEqual(expectation, valid)
        if expectation:
            self.assertEqual("", reason)
        else:
            if deprecated:
                self.assertEqual(True, "deprecated directive" in reason)
            else:
                self.assertEqual(name + " is an unknown directive.", reason)

    def test_default_src_in_directive(self):
        self._test("default-src", True, deprecated=False)

    def test_default_src_case_insentitive_in_directive(self):
        self._test("DeFault-srC", True, deprecated=False)

    def test_script_src_in_directive(self):
        self._test("script-src", True, deprecated=False)

    def test_unknown_src_not_in_directive(self):
        self._test("unknown_src", False, deprecated=False)
    
    def test_allow_deprecated_directive(self):
        self._test("allow", False, deprecated=True)

    def test_in_operator_only_matches_full_string(self):
        self._test("allow-src", False, deprecated=False)

class TestParseSourceList(unittest.TestCase):
    def _test(self, slist, expectation, expected_reason):
        valid, reason = csp.parse_source_list(slist)
        self.assertEqual(expectation, valid)
        if expectation:
            self.assertEqual(expected_reason, reason)
            self.assertEqual(expected_reason, "")

        else:
            self.assertTrue(expected_reason in reason)

    def test_self_is_parsable(self):
        self._test(["'self'"], True, "")

    def test_self_url_is_parsable(self):
        self._test(["'self'", "google.com"], True, "")

    def test_none_is_parsable(self):
        self._test(["'none'"], True, "")

    def test_none_url_not_parsable(self):
        self._test(["'none'", "google.com"], False, "should not be present.")

    def test_url_none_not_parsable(self):
        self._test(["google.com", "'none'"], False, "should not be present.")


class TestMatchSourceExpressions(unittest.TestCase):
    
    def _test(self, slist, valid, error):
        is_valid, reason = csp.match_source_expressions(slist)
        self.assertEqual(is_valid, valid)
        self.assertEqual(True, error in reason)

    def test_slist_with_just_self(self):
        self._test(["'self'"], True, "")

    def test_slist_with_self_and_uri(self):
        self._test(["'self'", "google.com"], True, "")

    def test_slist_with_self_without_quote_should_not_fail(self):
        # CSP allows hostname like self, localhost, mail
        self._test(["self", "google.com"], True, "")

    # issue #6
    def test_slist_with_second_item_fail_should_fail_check(self):
        self._test(["'self'", "'selfself'"], False, "invalid source expression")

    def test_slist_with_deprecated_keyword(self):
        self._test(["'self'", "'eval-script'"], False, "deprecated keyword source")

class TestValidate(unittest.TestCase):
    def _assert(self, policy, valid=None, fail_by_directive=None, fail_by_source=None, \
        directives=None, error_contain=None):
        r = csp.validate(policy)
        self.assertEqual(valid, r["valid"])
        if valid is False:
            if fail_by_directive:
                self._assert_directive_errors(r["errors"], directives, error_contain)
            elif fail_by_source:
                self._assert_source_errors(r["errors"], directives, error_contain)
        else:
            self.assertEqual([], r["errors"])

    def _assert_directive_errors(self, errors, directives, error_contain):
        self.assertTrue(len(directives) == len(errors) and len(directives) > 0)
        for index, directive in enumerate(directives):
            for index, error in enumerate(errors):
                if error["directive_name"] == directive:
                    self.assertEqual(True, error_contain in error["reason"])
                
    def _assert_source_errors(self, errors, directives, error_contain):
        self.assertTrue(len(directives) == len(errors) and len(directives) > 0)
        for index, directive in enumerate(directives):
            for index, error in enumerate(errors):
                if error["directive_name"] == directive:
                    self.assertEqual(True, error_contain in error["reason"])

    def test_policy_with_just_default_src(self):
        policy = "default-src 'self';"
        self._assert(policy, valid=True)

    def test_policy_with_default_src_ends_without_semicolon(self):
        policy = "default-src 'self'"
        self._assert(policy, valid=True)

    def test_policy_with_two_directives(self):
        policy = "default-src 'self' google.com; img-src *;"
        self._assert(policy, valid=True)

    def test_policy_with_unknown_directive(self):
        policy = "unknown-src 'self' google.com;"
        self._assert(policy, valid=False, directives=["unknown-src"], \
            fail_by_directive=True, error_contain="unknown directive")

    def test_policy_with_unkown_directive_as_second_directive(self):
        policy = "default-src 'self' google.com; unknown-src *;"
        self._assert(policy, valid=False, directives=["unknown-src"], \
            fail_by_directive=True, error_contain="unknown directive")

    def test_policy_with_invalid_src_expression(self):
        policy = "default-src 'self-invalid';"
        self._assert(policy, valid=False, fail_by_source=True, \
            directives=["default-src"], error_contain="invalid source expression")

    def test_policy_with_allow_self_deprecated_policy(self):
        policy = "default-src 'self'; allow 'self';"
        self._assert(policy, valid=False, fail_by_directive=True, \
            directives=["allow"], error_contain="deprecated directive")

    def test_policy_contains_inline_script_deprecated_keyword_source(self):
        policy = "default-src 'self'; script-src 'inline-script';"
        self._assert(policy, valid=False, fail_by_directive=True, \
            directives=["script-src"], error_contain="deprecated keyword source")


if __name__ == "__main__":
    unittest.main()
