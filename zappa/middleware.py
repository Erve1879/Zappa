import base58
import json
import time

from werkzeug.http import parse_cookie, dump_cookie
from werkzeug.wsgi import ClosingIterator

REDIRECT_HTML = """<!DOCTYPE HTML>
<html lang="en-US">
    <head>
        <meta charset="UTF-8">
        <meta http-equiv="refresh" content="1;url=REDIRECT_ME">
        <script type="text/javascript">
            window.location.href = "REDIRECT_ME"
        </script>
        <title>Page Redirection</title>
    </head>
    <body>
        <!-- Note: don't tell people to `click` the link, just tell them that it is a link. -->
        If you are not redirected automatically, follow the <a href='REDIRECT_ME'>link to example</a>
    </body>
</html>"""


class ZappaWSGIMiddleware(object):

    # Unpacked / Before Packed Cookies
    decoded_zappa = None
    request_cookies = {}

    start_response = None
    redirect_content = None

    def __init__(self, application):
        self.application = application

    def __call__(self, environ, start_response):
        """
        A note about the zappa cookie: Only 1 cookie can be passed through API
        Gateway. Hence all cookies are packed into a special cookie, the
        zappa cookie. There are a number of problems with this:

            * updates of single cookies, when there are multiple present results
              in deletion of the ones that are not being updated.
            * expiration of cookies. The client no longer knows when cookies
              expires.

        The first is solved by unpacking the zappa cookie on each request and
        saving all incoming cookies. The response Set-Cookies are then used
        to update the saved cookies, which are packed and set as the zappa
        cookie.

        The second is solved by filtering cookies on their expiration time,
        only passing cookies that are still valid to the WSGI app.
        """
        self.start_response = start_response

        # Parse cookies from the WSGI environment
        parsed = parse_cookie(environ)
        parsed.pop('zappa', None)
        self.request_cookies = parsed
        environ[u'HTTP_COOKIE'] = parsed
        # Call the application with our modifier
        response = self.application(environ, self.encode_response)

        # If we have a redirect, smash in our response content.
        if self.redirect_content:
            response = [self.redirect_content for item in response]

        self.redirect_content = None # Make sure that nothing is cached from a previous request

        # Return the response as a WSGI-safe iterator
        return ClosingIterator(
            response
        )

    def encode_response(self, status, headers, exc_info=None):
        """
        Zappa-ify our application response!

        This means:
            - Updating any existing cookies.
            - Packing all our cookies into a single ZappaCookie.
            - Injecting redirect HTML if setting a Cookie on a redirect.

        """
        # All the non-cookie headers should be sent unharmed.
        new_headers = [(header[0], header[1]) for header in headers if header[0] != 'Set-Cookie']

        # Filter the headers for Set-Cookie header
        cookie_dicts = [
            {header[1].split('=', 1)[0].strip():header[1].split('=', 1)[1]}
            for header
            in headers
            if header[0] == 'Set-Cookie'
        ]

        # Update request_cookies with cookies from the response. If there are
        # multiple occuring cookies, the last one present in the headers wins.
        map(self.request_cookies.update, cookie_dicts)
        return self.start_response(status, new_headers, exc_info)

    def decode_zappa_cookie(self, encoded_zappa):
        """
        Eat our Zappa cookie.
        Save the parsed cookies, as we need to send them back on every update.
        """
        self.decoded_zappa = base58.b58decode(encoded_zappa)
        self.request_cookies = json.loads(self.decoded_zappa)

    def filter_expired_cookies(self):
        """
        Remove any expired cookies from our internal state.

        The browser may send expired cookies, because it does not parse the
        the ZappaCookie into its constituent parts.
        """
        now = time.gmtime()  # GMT as struct_time
        for name, exp in self.iter_cookies_expires():
            if exp < now:
                del(self.request_cookies[name])

    def iter_cookies_expires(self):
        """
            Interator over request_cookies.
            Yield name and expires of cookies.
        """
        for name, value in self.request_cookies.items():
            if not isinstance(value, basestring):
                continue
            cookie = (name + '=' + value).encode('utf-8')
            if cookie.count('=') is 1:
                continue

            kvps = cookie.split(';')
            for kvp in kvps:
                kvp = kvp.strip()
                if 'expires' in kvp.lower():
                    try:
                        exp = time.strptime(kvp.split('=')[1], "%a, %d-%b-%Y %H:%M:%S GMT")
                    except ValueError:  # https://tools.ietf.org/html/rfc6265#section-5.1.1
                        exp = time.strptime(kvp.split('=')[1], "%a, %d-%b-%y %H:%M:%S GMT")
                    yield name, exp
                    break

    def cookie_environ_string(self):
        """
        Return the current set of cookies as a string for the HTTP_COOKIE environ.
        """
        str_list = [
            key + '=' + value for key, value in self.request_cookies.items()
            if isinstance(value, (str, unicode))
        ]
        return ';'.join(str_list)
