# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import socket
import time
import urlparse

class Vuln(ABVuln):
    vuln_id = 'IIS_0007' # 平台漏洞编号
    name = 'IIS WebDav RCE' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.RCE # 漏洞类型
    disclosure_date = '2017-08-22'  # 漏洞公布时间
    desc = '''
        CVE-2017-7269,Windows Server 2003R2版本IIS6.0的WebDAV服务中的ScStoragePathFromUrl
        函数存在缓存区溢出漏洞，远程攻击者通过以“If: <http://”开头的长header PROPFIND请求，执行任意代码，
        进而导致服务器被入侵控制。
    ''' # 漏洞描述
    ref = 'http://www.freebuf.com/vuls/130531.html' # 
    cnvd_id = 'Unkown ' # cnvd漏洞编号
    cve_id = 'CVE-2017-7269'  # cve编号
    product = 'IIS'  # 漏洞组件名称
    product_version = 'IIS WebDav RCE'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'c2413491-70bd-4f33-9660-e248de7b39e3' # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-01' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            url = urlparse.urlparse(arg)
            ip = socket.gethostbyname(url.hostname)
            port = url.port if url.port else 80
            timeout = 10
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, port))
            pay = "OPTIONS / HTTP/1.0\r\n\r\n"
            s.send(pay)
            data = s.recv(2048)
            s.close()
            if "PROPFIND" in data and "Microsoft-IIS/6.0" in data :
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
            
        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()