import re
import constant

def main(csp):
    """
    Main function to parse and validate the given Content
    Security Policy. 

    Parameters
    ----------
    csp : str
        The content security policy of interest.
    
    Returns
    -------
    is_valid : bool
        If the policy is parsed and correct according to
        the Content Security Policy grammar rule, return
        ``True``. Otherwise, ``False`` is return.

    """

    directives = parse_policy(csp)
    for directive in directives:
        if not validate_directive(directive):
            return False
    return True

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
    Return ``True`` if the directive name is correct according
    to CSP 1.0 specification.

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
    return match_source_expression(source_list)

def match_source_expression(source_list):
    return True
