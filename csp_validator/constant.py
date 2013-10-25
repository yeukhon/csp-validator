SCHEME_SOURCE = r"(https|http|data|blob|javascript|ftp)\:"
HOST_SOURCE = r'((https|http|data|blob|javascript|ftp)\:\/\/)?((\*\.)?[a-z0-9\-]+(\.[a-z0-9\-]+)*|\*)(\:(\*|[0-9]+))?'
KEYWORD_SOURCE = r"('self'|'unsafe-inline'|'unsafe-eval')"

DIRECTIVES = ("default-src", "script-src", "style-src", "object-src", "img-src", \
    "media-src", "frame-src", "font-src", "connect-src", "report-uri")

DEPRECATED_DIRECTIVES = ("allow",)
