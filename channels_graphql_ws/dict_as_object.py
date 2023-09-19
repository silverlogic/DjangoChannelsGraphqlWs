# Copyright (C) DATADVANCE, 2010-2023
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

"""Dict wrapper to access keys as attributes."""
from urllib.parse import urljoin, urlsplit
from django.utils.encoding import escape_uri_path, iri_to_uri
from django.utils.functional import cached_property
from django.conf import settings
from django.core.exceptions import DisallowedHost
from django.http.request import split_domain_port, validate_host


class DictAsObject:
    """Dict wrapper to access keys as attributes."""

    def __init__(self, scope):
        """Remember given `scope`."""
        self._scope = scope

    def _asdict(self):
        """Provide inner Channels scope object."""
        return self._scope

    # ------------------------------------------------ WRAPPER FUNCTIONS
    def __getattr__(self, name):
        """Route attributes to the scope object."""
        if name.startswith("_"):
            raise AttributeError()
        try:
            return self._scope[name]
        except KeyError as ex:
            try:
                return self._scope["channels_scope"][name]
            except KeyError:
                raise AttributeError() from ex

    def __setattr__(self, name, value):
        """Route attributes to the scope object."""
        if name.startswith("_"):
            super().__setattr__(name, value)
        self._scope[name] = value

    # ----------------------------------------------------- DICT WRAPPER
    def __getitem__(self, key):
        """Wrap dict method."""
        return self._scope[key]

    def __setitem__(self, key, value):
        """Wrap dict method."""
        self._scope[key] = value

    def __delitem__(self, key):
        """Wrap dict method."""
        del self._scope[key]

    def __contains__(self, item):
        """Wrap dict method."""
        return item in self._scope

    def __str__(self):
        """Wrap dict method."""
        return self._scope.__str__()

    def __repr__(self):
        """Wrap dict method."""
        return self._scope.__repr__()

    # ---------------------------- build_absolute_uri
    # copy from django.http.request.HttpRequest so we can have build_absolute_uri on channels scope

    def build_meta(self):
        """Build META dict from headers."""
        META = {}
        for key, value in self.channels_scope.get('headers', []):
            META[key.decode("utf-8").replace("-", "_").upper()] = value.decode("utf-8")
        META['QUERY_STRING'] = self.channels_scope.get('query_string', b'').decode("utf-8")
        self.META = META

    def build_absolute_uri(self, location=None):
        """
        Build an absolute URI from the location and the variables available in
        this request. If no ``location`` is specified, build the absolute URI
        using request.get_full_path(). If the location is absolute, convert it
        to an RFC 3987 compliant URI and return it. If location is relative or
        is scheme-relative (i.e., ``//example.com/``), urljoin() it to a base
        URL constructed from the request variables.
        """
        if location is None:
            # Make it an absolute url (but schemeless and domainless) for the
            # edge case that the path starts with '//'.
            location = "//%s" % self.get_full_path()
        else:
            # Coerce lazy locations.
            location = str(location)
        bits = urlsplit(location)
        if not (bits.scheme and bits.netloc):
            # Handle the simple, most common case. If the location is absolute
            # and a scheme or host (netloc) isn't provided, skip an expensive
            # urljoin() as long as no path segments are '.' or '..'.
            if (
                bits.path.startswith("/")
                and not bits.scheme
                and not bits.netloc
                and "/./" not in bits.path
                and "/../" not in bits.path
            ):
                # If location starts with '//' but has no netloc, reuse the
                # schema and netloc from the current request. Strip the double
                # slashes and continue as if it wasn't specified.
                location = self._current_scheme_host + location.removeprefix("//")
            else:
                # Join the constructed URL with the provided location, which
                # allows the provided location to apply query strings to the
                # base path.
                location = urljoin(self._current_scheme_host + self.path, location)
        return iri_to_uri(location)

    def get_full_path(self, force_append_slash=False):
        return self._get_full_path(self.path, force_append_slash)

    def _get_full_path(self, path, force_append_slash):
        # RFC 3986 requires query string arguments to be in the ASCII range.
        # Rather than crash if this doesn't happen, we encode defensively.
        return "%s%s%s" % (
            escape_uri_path(path),
            "/" if force_append_slash and not path.endswith("/") else "",
            ("?" + iri_to_uri(self.META.get("QUERY_STRING", "")))
            if self.META.get("QUERY_STRING", "")
            else "",
        )

    def is_secure(self):
        return not settings.DEBUG

    @cached_property
    def _current_scheme_host(self):
        return "{}://{}".format("https" if self.is_secure() else "http", self.get_host())

    def get_host(self):
        """Return the HTTP host using the environment or request headers."""
        host = self._get_raw_host()

        # Allow variants of localhost if ALLOWED_HOSTS is empty and DEBUG=True.
        allowed_hosts = settings.ALLOWED_HOSTS
        if settings.DEBUG and not allowed_hosts:
            allowed_hosts = [".localhost", "127.0.0.1", "[::1]"]

        domain, port = split_domain_port(host)
        if domain and validate_host(domain, allowed_hosts):
            return host
        else:
            msg = "Invalid HTTP_HOST header: %r." % host
            if domain:
                msg += " You may need to add %r to ALLOWED_HOSTS." % domain
            else:
                msg += (
                    " The domain name provided is not valid according to RFC 1034/1035."
                )
            raise DisallowedHost(msg)

    def _get_raw_host(self):
        """
        Return the HTTP host using the environment or request headers. Skip
        allowed hosts protection, so may return an insecure host.
        """

        # We try three options, in order of decreasing preference.
        if settings.USE_X_FORWARDED_HOST and ("X_FORWARDED_HOST" in self.META):
            host = self.META["X_FORWARDED_HOST"]
        elif "HOST" in self.META:
            host = self.META["HOST"]
        else:
            host = "localhost"
            # # Reconstruct the host using the algorithm from PEP 333.
            # host = self.META["SERVER_NAME"]
            # server_port = self.get_port()
            # if server_port != ("443" if self.is_secure() else "80"):
            #     host = "%s:%s" % (host, server_port)
        return host
