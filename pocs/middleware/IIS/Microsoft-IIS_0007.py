# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import socket
import time
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'Microsoft-IIS_0007'  # 平台漏洞编号
    name = 'Microsoft-IIS缓冲区溢出漏洞(CNVD-2017-03467)'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2017-08-22'  # 漏洞公布时间
    desc = '''
        Microsoft Windows Server 2003 R2是美国微软（Microsoft）公司发布的一套服务器操作系统。Internet Information Services（IIS）是一套运行于Microsoft Windows中的互联网基本服务。
        在Windows Server 2003 R2的IIS 6.0版本中的WebDAV服务的ScStoragePathFromUrl函数存在缓冲区溢出漏洞，攻击者可通过一个以“If: <http://”开始的较长header头的PROPFIND请求执行任意代码。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2017-03467'
    cnvd_id = 'CNVD-2017-03467'  # cnvd漏洞编号
    cve_id = 'CVE-2017-7269'  # cve编号
    product = 'Microsoft-IIS'  # 漏洞组件名称
    product_version = 'IIS WebDav RCE'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'c2413491-70bd-4f33-9660-e248de7b39e3'  # 平台 POC 编号
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
            arg = '{target}'.format(target=self.target)
            url = urllib.parse.urlparse(arg)
            ip = socket.gethostbyname(url.hostname)
            port = url.port if url.port else 80
            timeout = 10
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, port))
            pay = "OPTIONS / HTTP/1.0\r\n\r\n"
            s.send(pay)
            data = s.recv(2048)
            s.close()
            if "PROPFIND" in data and "Microsoft-IIS/6.0" in data:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
