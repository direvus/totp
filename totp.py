"""Generate time-based one-time passwords per RFC 6238."""
from calendar import timegm
from os import urandom
from time import gmtime
import hashlib
import hmac
import struct


DEFAULT_TIME_STEP = 30
DEFAULT_EPOCH = 0
DEFAULT_DIGITS = 6


def current_timestamp_utc():
    """Return the current time in UTC as integer seconds since Epoch."""
    return int(timegm(gmtime()))


def time_steps(current=None, epoch=DEFAULT_EPOCH, step=DEFAULT_TIME_STEP):
    """Return the number of time steps for a given timestamp.

    By default, this will return the number of whole 30-second increments since
    the Unix Epoch in UTC, according to the current system clock time.
    """
    if current is None:
        current = current_timestamp_utc()
    return (long(current) - int(epoch)) / int(step)


def hmac_digest(key, message, hashfunc=hashlib.sha1):
    """Return a HMAC binary digest string for the given key and message.

    If the message is given as an integer, it will be converted to an 8-byte
    string for input into the HMAC function.
    """
    if isinstance(message, int) or isinstance(message, long):
        message = struct.pack('>Q', message)
    return hmac.new(key, message, hashfunc).digest()


def truncate(digest, digits=DEFAULT_DIGITS):
    """Return a short code from a HMAC digest.

    Using dynamic truncation according to RFC 4226, take a binary HMAC digest
    string of 20 bytes, and calculate a short numeric code with the given
    number of digits.
    """
    # Get an offset from the low-order 4 bits of the final byte
    byte = struct.unpack('B', digest[-1])[0]
    offset = byte & 15

    # Extract a four-byte string using the offset
    codestr = digest[offset:offset+4]

    # Convert to integer, and mask the high-order bit
    code = struct.unpack('>I', codestr)[0]
    code = code & ~(1 << 31)

    return code % (10 ** digits)


def hotp(key, counter, hashfunc=hashlib.sha1):
    """Return an RFC 4226 HOTP token for the given key and counter values."""
    return truncate(hmac_digest(key, counter, hashfunc))


def totp(key, current=None, epoch=DEFAULT_EPOCH, step=DEFAULT_TIME_STEP):
    """Return an RFC 6238 TOTP token for the given key and timing values.

    Calculate the number of time steps between the current time and the Epoch
    time.  By default this is the number of 30-second increments between the
    current system clock time in UTC and the Unix Epoch.
    """
    return hotp(key, time_steps(current, epoch, step))


def generate_key(size=20):
    """Return a randomly-generated key value of 'size' bytes.

    The byte values are generated using os.urandom, which draws from the
    system's source of random data.  This function can only be relied upon to
    generate cryptographically robust random keys on systems where SystemRandom
    yields high-quality random data.
    """
    return urandom(size)
