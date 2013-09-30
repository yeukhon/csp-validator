import unittest
import csp

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

    def test_slist_with_self_without_quote_should_fail(self):
        self._test(["self", "google.com"], False)

class TestMain(unittest.TestCase):
    
    def test_policy_with_just_default_src(self):
        policy = "default-src 'self';"
        d = csp.main(policy)
        self.assertEqual(True, d)

    def test_policy_with_default_src_ends_without_semicolon(self):
        policy = "default-src 'self'"
        d = csp.main(policy)
        self.assertEqual(True, d)

    def test_policy_with_two_directives(self):
        policy = "default-src 'self' google.com; img-src *;"
        d = csp.main(policy)
        self.assertEqual(True, d)

    def test_policy_with_unknown_directive(self):
        policy = "unknown-src 'self' google.com;"
        d = csp.main(policy)
        self.assertEqual(False, d)

    def test_policy_with_unkown_directive_as_second_directive(self):
        policy = "default-src 'self' google.com; unknown-src *;"
        d = csp.main(policy)
        self.assertEqual(False, d)


