# -*- coding: utf-8 -*-

import copy
import email
import urllib.parse
from io import StringIO
import requests


def parse_header(headers: str):
    return dict(email.message_from_file(StringIO(headers)).items())


def to_raw_req(resp):
    req = resp.request
    result = '{}\r\n{}'.format(
        req.method + ' ' + req.url,
        '\n'.join('{}: {}'.format(k, v) for k, v in req.headers.items()))
    if req.body:
        result = '{}\r\n\r\n{}'.format(result, req.body)
    return result


def to_raw_resp(resp):
    result = ('HTTP/%.1f {} {}\r\n{}' %
              resp.raw.version).format(resp.status_code, resp.reason,
                                       '\n'.join('{}: {}'.format(k, v)
                                                 for k, v in resp.headers.items()))
    if resp.text:
        result = '{}\r\n\r\n{}'.format(result, resp.text)
    return result


class hackhttp():

    def __init__(self, conpool=None, cookie_str=None, throw_exception=True):
        """
        :param conpool: 创建的连接池最大数量，类型为 int，默认为 10
        :param cookie_str: 用户自己定义的 Cookie，类型为 String
        :param throw_exception: 是否抛出遇到的异常，类型为 bool，默认为 True
        """
        self.conpool = conpool
        self.cookie_str = cookie_str
        self.throw_exception = throw_exception

    def http(self, url, post=None, **kwargs):
        '''hh.http(...) -> (code, head, html, redirtct_url, log)

        Send an HTTP Request.

        kwargs:

            *********

            param: post: Set http POST data.

            eg:
                post = "key1=val1&key2=val2"

            *********

            param: header:
            param: headers:  Set http headers. If you set header, headers will drop.

            eg:

                header = 'Referer:https://bugscan.net\r\nUser-Agent: hackhttp user-agent'

            eg:
                headers={
                    'Referer': 'https://bugscan.net',
                    'User-Agent': 'hackhttp user-agent'
                }

            *********

            param: method: Set HTTP Request Method, default value is 'GET'.
            If the param "post" is set, the method will auto change to 'POST'
            The value of this param you can find it in RFC2616.

            Method List:
                OPTIONS, GET, HEAD, POST,
                PUT, DELETE, TRACE, CONNECT

            eg:
                method = 'POST'

            *********

            param: raw: Set HTTP raw package.

            eg:
                raw = """POST /post HTTP/1.1
                Host: httpbin.org
                User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:45.0) Gecko/20100101 Firefox/45.0
                Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
                Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
                Accept-Encoding: gzip, deflate
                Connection: close
                Content-Type: application/x-www-form-urlencoded
                Content-Length: 19

                key1=val1&key2=val2"""

            *********

            param: proxy: Set HTTP Proxy, support http protocol.

            eg:
                proxy = ('127.0.0.1', 9119)

            *********

            param:cookcookie: Auto set cookie and get cookie.

            cookcookie=True

            *********

            param: location: Auto redirect when 302.

            eg:
                location=True

            *********

            param: throw_exception: Throw exception or pass when exception occurred.
            eg:
                throw_exception=True

            *********

            param: data: HTTP Request Data，when param is None.

            eg, application/x-www-form-urlencoded :

                data="key1=val1&key2=val2"

            eg, application/json:

                data='{"key1": "val1", "key2": "val2"}'

        '''
        headers = kwargs.get('header', '') or kwargs.get('headers', {})
        method = kwargs.get('method', None)
        raw = kwargs.get('raw', None)
        proxy = kwargs.get('proxy', None)
        if not post:
            post = kwargs.get('data', None)
        cookcookie = kwargs.get('cookcookie', True)
        location = kwargs.get('location', True)
        throw_exception = kwargs.get('throw_exception', self.throw_exception)

        if headers and isinstance(headers, str):
            headers = parse_header(headers)
        for arg_key, h in[
                ('cookie', 'Cookie'),
                ('referer', 'Referer'),
                ('user_agent', 'User-Agent'), ]:
            if kwargs.get(arg_key):
                headers[h] = kwargs.get(arg_key)
        try:
            return self.httpraw(
                url, raw=raw, proxy=proxy, cookcookie=cookcookie,
                location=location) if raw else self._http(
                    url, post=post, headers=headers, method=method,
                    proxy=proxy, cookcookie=cookcookie,
                    location=location)
        except:
            if throw_exception:
                raise
            else:
                return 0, '', '', '', {'url': '', 'request': '', 'response': ''}

    def _http(self, url, post=None, headers={}, method=None,
              proxy=None, cookcookie=True, location=True):
        method = method or ('POST' if post else 'GET')
        tmpheaders = copy.deepcopy(headers)
        tmpheaders['Accept-Encoding'] = 'gzip, deflate'
        tmpheaders['Connection'] = 'Keep-Alive'
        tmpheaders['User-Agent'] = tmpheaders['User-Agent'] if tmpheaders.get(
            'User-Agent') else 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.71 Safari/537.36'

        resp = None
        if post:
            resp = requests.request(method, url, allow_redirects=location,
                                    headers=tmpheaders, data=post)
        else:
            resp = requests.request(
                method, url, allow_redirects=location, headers=tmpheaders)
        return resp.status_code, resp.headers, resp.text, resp.url, {'url': url, 'response': to_raw_resp(resp), 'request': to_raw_req(resp)}

    def httpraw(self, url, raw, proxy=None, cookcookie=True, location=True):
        https, host, port, path = self._get_urlinfo(url)
        raw = StringIO(raw.lstrip())
        requestline = raw.readline().rstrip()
        words = requestline.split()
        if len(words) == 3:
            command, _, _ = words
        elif len(words) == 2:
            command, _ = words
        else:
            raise Exception('http raw parse error')
        headers = parse_header(raw)
        rawbody = ''
        content_type = headers.get('Content-Type', "")
        # Content-Type: application/x-www-form-urlencoded
        # Content-Type: multipart/form-data
        if content_type.startswith('application/x-www-form-urlencoded'):
            while 1:
                line = raw.readline()
                if line == '':
                    rawbody = rawbody[:-2]
                    break
                rawbody += line.rstrip() + '\r\n'
        if content_type.startswith('multipart/form-data'):
            while 1:
                line = raw.readline()
                if line == '':
                    break
                if line[:2] == "--":
                    if rawbody != "" and rawbody[-2:] != '\r\n':
                        rawbody = rawbody[:-1] + '\r\n'
                    rawbody += line.rstrip() + '\r\n'
                elif line[:8].lower() == 'content-':
                    rawbody += line.rstrip() + '\r\n'
                    line = raw.readline()
                    if line[:8].lower() == 'content-':
                        rawbody += line.rstrip() + '\r\n'
                        raw.readline()
                    rawbody += '\r\n'
                else:
                    rawbody += line
        headers['Host'] = host
        headers['Content-Length'] = str(len(rawbody))
        return self._http(
            url, post=rawbody, headers=headers, method=command,
            proxy=proxy, cookcookie=cookcookie, location=location)

    def _get_urlinfo(self, url):
        p = urllib.parse.urlparse(url)
        scheme = p.scheme.lower()
        if scheme not in ('http', 'https'):
            raise Exception('http/https only')
        host = p.hostname
        port = p.port
        https = True if scheme == "https" else False
        if not port:
            port = 443 if https else 80
        path = ''
        if p.path:
            path = p.path
            if p.query:
                path = path + '?' + p.query
        return https, host, port, path
