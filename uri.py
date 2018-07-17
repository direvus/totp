"""Generate key URIs for TOTP."""
from base64 import b32encode
try:
    from urllib import urlencode, quote
except ImportError:
    # Thanks for this charming work-around, Python3
    from urllib.parse import urlencode, quote


def key_uri(key, issuer, accountname, digits, step):
    """Return a TOTP URI for importing a key into a token application.

    The URI is produced according to Google Authenticator's Key URI format [1],
    and is suitable for rendering as a QR code.

    [1] https://github.com/google/google-authenticator/wiki/Key-Uri-Format
    """
    params = {
        'secret': b32encode(key),
        'issuer': issuer,
        'algorithm': 'SHA1',
        'digits': digits,
        'period': step}
    return 'otpauth://totp/{}:{}?{}'.format(
        quote(issuer),
        quote(accountname),
        urlencode(params))
