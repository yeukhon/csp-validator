# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import re
import constant

def validate(csp):
    """
    Main function to parse and validate the given Content
    Security Policy. 

    Parameters
    ----------
    csp : str
        The content security policy of interest.
    
    Returns
    -------
    result : dict
        A dictionary with two keys ("valid", "errors"). The
        structure of the dictionary is documented as follows:
        
        {
            valid: True/False,
            errors: [
                        {
                            directive_name: str,
                            reason: str
                        }
                    ]
        }

    """

    result = {
        "errors": []
    }
    
    directives = parse_policy(csp)
    for directive in directives:
        valid, reason = validate_directive(directive)
        if not valid:
            result["errors"].append({
                "directive_name": directive,
                "reason": reason
            })
        valid, reason = parse_source_list(directives[directive])
        if not valid:
            result["errors"].append({
                "directive_name": directive,
                "reason": reason
            })

    if result["errors"]:
        result["valid"] = False
    else:
        result["valid"] = True
    return result

def parse_policy(csp):
    """
    Return a dictionary of directives with a list
    of directive values for each directive
    discovered. 

    Parameters
    ----------
    csp : str
        The content security policy of interest.

    Returns
    -------
    directives : dict
        A dictionary of directives with a list
        of directive values.

    """
    
    r1 = re.compile(';\s*')
    r2 = re.compile('\s+')

    # individual directives should be split by ;
    dir_split_list = r1.split(csp)
    # the last item could be empty if ; is present
    dir_split_list = filter(None, dir_split_list)
    
    # split by space so directive name is first element
    # follows by a list of source expressions
    directives = {}
    for index, directive_group in enumerate(dir_split_list):
        d = r2.split(directive_group)
        directives[d[0]] = d[1:]
    return directives


def validate_directive(directive):
    """

    Determine whether the given directive is one of the 
    documented directive in the Content Security
    Policy 1.0 specification. 

    Deprecated directives are also check and a different
    error is returned for deprecated directive.

    Parameters
    ----------
    directive : str
        The name of the directive
    
    Returns
    -------
    is_valid : bool
        If the name of the directive exists in the 1.0
        specification, return ``True``. Otherwise,
        return ``False``.

    reason : str
        If the directive is valid, reason is empty. If
        directive is invalid, we return a reason so that
        ``validate`` append the reason to its corresponding
        error.

    """

    is_valid = directive.lower() in constant.DIRECTIVES
    if is_valid:
        return is_valid, ""
    else:
        if directive.lower() in constant.DEPRECATED_DIRECTIVES:
            return is_valid, "%s is a deprecated directive." % directive
        return is_valid, "%s is an unknown directive." % directive

def parse_source_list(source_list):
    """
    Parse the given source list and return ``True`` if the source
    list is completely valid. Otherwise return ``False``.

    Parameters
    ----------
    source_list : list
        A list of directive values.

    Returns
    -------
    is_valid : bool
    reason : str
        If the directive is valid, return an empty reason. If
        the source list contains invalid entity, return
        an error message.
 
    """

    # when 'none' is applied no other source expressions are 
    # allowed (UA is supposed to fail such rule).
    if "'none'" in source_list:
        if len(source_list) > 1:
            return False, "When 'none' is present, other source expressions should not be present."
        else:
            return True, ""

    # match a source expression via the CSP grammar
    valid, reason = match_source_expressions(source_list)
    return valid, reason

def match_source_expressions(source_list):
    """
    Determine whether the source list matches source expressions.
    Iterate each source list element (uri) to a source expression
    according the CSP grammar.

    Parameters
    ----------
    source_list : list
        A list of directive values.
    
    Returns
    -------
    matched : bool
    reason: str
        If there is an invalid source expression in the list,
        an error message is returned. Otherwise, empty string
        is returned.

    """

    # wildcard has superpower 
    if source_list and source_list[0] == "*":
        return True, ""

    for index, uri in enumerate(source_list):
        uri = uri.lower()
        is_scheme_src = match(uri, constant.SCHEME_SOURCE)
        is_keyword_src = match(uri, constant.KEYWORD_SOURCE)
        is_host_src = match(uri, constant.HOST_SOURCE)
        if not any((is_scheme_src, is_keyword_src, is_host_src)):
            if uri in constant.DEPRECATED_KEYWORD_SOURCE:
                return False, "%s is a deprecated keyword source." % uri
            else:
                return False, "%s is an invalid source expression." % uri
    return True, ""

def match(uri, regex):
    """
    Decide whether uri matches one of the classes
    of regex. If a match is found and match matches
    the full uri string, return True. Otherwise, return
    False.
    
    Parameters
    ----------
    uri : str
    regex : str

    Returns
    -------
    matched : bool

    """
    r = re.compile(regex)
    m = r.match(uri)
    if m and m.group() == uri:
        return True
    else:
        return False

