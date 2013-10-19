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
        if not validate_directive(directive):
            result["errors"].append({
                "directive_name": directive,
                "reason": "%s is an unknown directive."
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

    """

    is_valid = directive.lower() in constant.DIRECTIVES
    return is_valid

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
    
    """

    # when 'none' is applied no other source expressions are 
    # allowed (UA is supposed to fail such rule).
    if "'none'" in source_list:
        if len(source_list) > 1:
            return False
        else:
            return True
    # match a source expression via the CSP grammar
    return match_source_expressions(source_list)

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

    """

    # wildcard has superpower 
    if source_list and source_list[0] == "*":
        return True

    for index, uri in enumerate(source_list):
        uri = uri.lower()
        is_scheme_src = match(uri, constant.SCHEME_SOURCE)
        is_keyword_src = match(uri, constant.KEYWORD_SOURCE)
        is_host_src = match(uri, constant.HOST_SOURCE)
        if any((is_scheme_src, is_keyword_src, is_host_src)):
            return True
        else:
            return False

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
