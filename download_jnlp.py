from datetime import datetime
import re
import requests
import datetime
import json
import argparse
import sys

def supermicro_x8(host, password, user="ADMIN"):
    result = {
        "success": False,
        "content": None,
        "reason": None,
        'type': None
    }
    url = "https://%s" % host
    data = {
        "WEBVAR_USERNAME": user,
        "WEBVAR_PASSWORD": password
    }
    sess = requests.Session()
    try:
        auth = sess.post(url=url + "/rpc/WEBSES/create.asp", data=data, verify=False, timeout=GET_TIMEOUT)
    except requests.exceptions.SSLError:
        try:
            url = "http://%s" % host
            auth = sess.post(url=url + "/rpc/WEBSES/create.asp", data=data, verify=False, timeout=GET_TIMEOUT)
        except:
            result["success"] = False
            result["reason"] = "SSL error and http error"
            return result
    
    jnlp = re.compile('<jnlp.*>.*<\/jnlp>', re.DOTALL)
    cookie = re.search("'SESSION_COOKIE' : '(.*)'", auth.content.decode()).group(1)
    sess.cookies.set("SessionCookie", cookie)
    sess.cookies.set("Username", user)
    
    java_file = sess.get(url=url + "/Java/jviewer.jnlp?EXTRNIP=%s&JNLPSTR=JViewer" % host, verify=False, timeout=GET_TIMEOUT)
    content = java_file.content.decode()
    if java_file.status_code == 405:
        result["success"] = False
        result["reason"] = "Authentication failed"
    
    if jnlp.search(content):
        result["success"] = True
        result["type"] = 'java'
        result["content"] = content.strip()
    
    return result


def supermicro_x9_10_11_12(host, password, user="ADMIN"):
    result = {
        "success": False,
        "content": None,
        "reason": None,
        'type': None
    }
    url = "https://%s" % host
    headers = {
        "Referer": url,
    }
    
    data = {
        "name": user,
        "pwd": password
    }
    
    check = re.compile('SessionTimeout\(\);')
    jnlp = re.compile('<jnlp.*>.*<\/jnlp>', re.DOTALL)
    sess = requests.Session()
    sess.post(url=url + "/cgi/login.cgi", headers=headers, data=data, verify=False, timeout=GET_TIMEOUT)
    java_file = sess.get(url=url + "/cgi/url_redirect.cgi?url_name=ikvm&url_type=jwsk", headers=headers, verify=False, timeout=GET_TIMEOUT)
    content = java_file.content.decode()
    if check.search(content):
        result["reason"] = "Authentication failed"
    
    if jnlp.search(content):
        result["success"] = True
        result["type"] = 'java'
        result["content"] = content.strip()
    
    return result

# def supermicro_x10_11_12_html5(host, password, user="ADMIN"):
#     # https://X.X.X.X/cgi/url_redirect.cgi?url_name=man_ikvm_html5_bootstrap#
#     # Cookie: SID=xxxxxx
#     # CSRF_TOKEN: xxxxx
#     pass

# Not work =(
# def dell_idrac8_html(host, password, user="root"):
#     import urllib.parse
#     result = {
#         "success": False,
#         "content": None,
#         "reason": None,
#         'type': None
#     }
    
#     tokens = re.compile('<forwardUrl>index.html\?ST1=(?P<st1>.*),ST2=(?P<st2>.*)</forwardUrl>')
#     url = "https://%s" % host
#     data = {
#         "user": user,
#         "password": password
#     }
    
#     jnlp = re.compile('<jnlp.*>.*<\/jnlp>', re.DOTALL)
    
#     sess = requests.Session()
#     auth = sess.post(url=url + "/data/login", data=data, verify=False, timeout=GET_TIMEOUT)
#     auth_content = auth.content.decode()    
#     if re.search('<authResult>5<\/authResult>', auth_content):
#         result["success"] = False
#         result['reason'] = 'Authentication failed'
#         return result
    
#     if re.search('<authResult>1<\/authResult>', auth_content):
#         result["success"] = False
#         result['reason'] = 'Authentication failed'
#         return result
    
#     st1 = tokens.search(auth_content).group('st1')
    
#     HTML5, link not work
#     st2 = tokens.search(auth_content).group('st2')
#     session = sess.post(url + '/session?getSsnVar=aimSession', verify=False, headers={"ST2":st2})
#     params = {
#         "ipAddr": host,
#         "kvmPort": 5900,
#         "vmPriv": True,
#         "title": "idrac %s, ,User: %s" % (host, user),
#         "lang": "en",
#         "aimSession": json.loads(session.content.decode())["getSsnVar"]["aimSession"],
#         "ST2": st2,
#         "TokenName": "ST1",
#         "TokenKey": st1
#     }
    
#     html5 = "https://%s/virtualconsolehtml5.html?" % host
#     html5 += urllib.parse.urlencode(params)
#     print(html5)
#     pass

def dell_idrac8(host, password, user="root"):
    result = {
        "success": False,
        "content": None,
        "reason": None,
        'type': None
    }
    tokens = re.compile('<forwardUrl>index.html\?ST1=(?P<st1>.*),ST2=(?P<st2>.*)</forwardUrl>')
    url = "https://%s" % host
    data = {
        "user": user,
        "password": password
    }
    
    jnlp = re.compile('<jnlp.*>.*<\/jnlp>', re.DOTALL)
    
    sess = requests.Session()
    auth = sess.post(url=url + "/data/login", data=data, verify=False, timeout=GET_TIMEOUT)
    auth_content = auth.content.decode()    
    if re.search('<authResult>5<\/authResult>', auth_content):
        result["success"] = False
        result['reason'] = 'Authentication failed'
        return result
    
    if re.search('<authResult>1<\/authResult>', auth_content):
        result["success"] = False
        result['reason'] = 'Authentication failed'
        return result
    
    st1 = tokens.search(auth_content).group('st1')
    url = url + "/viewer.jnlp(%s@0@%s+User:+%s@%s@ST1=%s)" % (host, host, user, datetime.datetime.now().microsecond, st1)
    java_file = sess.get(url=url, verify=False, timeout=GET_TIMEOUT)
    content = java_file.content.decode()
    if jnlp.search(content):
        result["success"] = True
        result["type"] = 'java'
        result["content"] = content.strip()
    
    return result


def dell_idrac9(host, password, user="root"):
    result = {
        "success": False,
        "content": None,
        "reason": None,
        'type': None
    }
    url = "https://%s" % host

    headers = {
        "user": user,
        "password": password
    }
    
    jnlp = re.compile('<jnlp.*>.*<\/jnlp>', re.DOTALL)
    link = re.compile('"Location":"https:\/\/.*:5900\/index\.html'.format(host))
    
    sess = requests.Session()
    auth = sess.post(url=url + "/sysmgmt/2015/bmc/session", headers=headers, verify=False, timeout=GET_TIMEOUT)
    try:
        headers["XSRF-TOKEN"] = auth.headers["XSRF-TOKEN"]
    except KeyError:
        result["success"] = False
        result["reason"] = 'Authentication failed'
    else:
        console = sess.get(url=url + "/sysmgmt/2015/server/vconsole", verify=False, headers=headers, timeout=GET_TIMEOUT)
        content = console.content.decode()
        if jnlp.search(content):
            result["success"] = True
            result["type"] = 'java'
            result["content"] = content.strip()
        
        if link.search(content):
            result["success"] = True
            result["type"] = 'html5'
            result["content"] = json.loads(content)["Location"].strip()

    return result

def asrock_java(host, password, user="admin"):
    result = {
        "success": False,
        "content": None
    }
    url = "https://%s" % host

    headers = {}
    
    data = {
        "username": user,
        "password": password
    }
    
    jnlp = re.compile('<jnlp.*>.*<\/jnlp>', re.DOTALL)

    sess = requests.Session()
    # X570
    try:
        auth = sess.post(url=url + "/api/session", data=data, verify=False, timeout=GET_TIMEOUT)
        headers["X-CSRFTOKEN"] = json.loads(auth.content.decode())["CSRFToken"]
        headers["Cookie"] = "i18next=ru-ru; QSESSIONID=%s; lang=en-US; refresh_disable=1" % auth.cookies.get_dict()["QSESSIONID"]
        java_file = sess.get(url=url + "/api/remote_control/get/kvm/launch", headers=headers, verify=False, timeout=GET_TIMEOUT)
        java_file.raise_for_status()
    except KeyError:
        result['reason'] = "Authentication failed"
    except requests.HTTPError as e:
        # scheme two for X470
        if e.response.status_code == 404:
            java_file = sess.get(url=url + "/api/asrr/java-console", headers=headers, verify=False, timeout=GET_TIMEOUT)
            content = java_file.content.decode()
            if jnlp.search(content):
                result["success"] = True
                result["content"] = content.strip()
                result['type'] = 'java'
    except Exception as e:
        result['reason'] = str(e)
    else:
        content = java_file.content.decode()
        result["success"] = True
        result["content"] = content
        result['type'] = 'java'
    
    return result

def asrock_console(host, password, user="admin"):
    result = {
        "success": "failed",
        "content": None,
        "reason": None,
        "type": None
    }
    url = "https://%s" % host

    headers = {
        "Referer": url,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36",
        "Content-type": "application/x-www-form-urlencoded"
    }
    
    data = {
        "username": user,
        "password": password
    }
    
    sess = requests.Session()
    auth = sess.post(url=url + "/api/previewer", headers=headers, data=data, verify=False, timeout=GET_TIMEOUT)
    console = url + "/viewer.html?" + json.loads(auth.content.decode())["CSRFToken"]
    if auth.status_code == 200:
        result["success"] = True
        result["content"] = console
    else:
        result["reason"] = auth.status_code
        
    return result

def huawei(host, password, user="admin"):
    result = {
        "success": "failed",
        "content": None,
        "reason": None,
        "type": None
    }
    url = "https://%s" % host
    data = {
        "check_pwd": password,
        "user_name": user,
        "func": "AddSession",
        "IsKvmApp": 0,
        "logtype": 0
    }
    
    jnlp = re.compile('<jnlp.*>.*<\/jnlp>', re.DOTALL)
    sess = requests.Session()
    sess.post(url + "/bmc/php/processparameter.php", data=data, verify=False)
    java_file = sess.get(url + "/bmc/pages/remote/kvm.php?kvmmode=1&kvmway=0", verify=False)
    content = java_file.content.decode()
    if re.search('<title>iBMC Login</title>', content):
        result["reason"] = "Authentication failed"
    
    if jnlp.search(content):
        result["success"] = True
        result["content"] = content
        result["type"] = "java"
    
    return result

def detect_ipmi(host):
    url = "https://%s" % host
    ipmi_type = "unknown"
    try:
        page = requests.get(url, verify=False, allow_redirects=False, timeout=DETECT_TIMEOUT)
    except requests.exceptions.SSLError:
        url = "http://%s" % host
        page = requests.get(url, verify=False, allow_redirects=False, timeout=DETECT_TIMEOUT)
    
    dell8 = re.compile(b"<p>The document has moved <a href=\".*/start.html\">here</a>\.</p></body></html>")
    dell9 = re.compile(b"<p>The document has moved <a href=\".*/restgui/start\.html\">here</a>\.</p>")
    supermicro_x8 = re.compile(b"<a href=\".*/login.asp\">location</a>")
    supermicro_x9 = re.compile(b"<form name=\"form1\" action=\"/cgi/login.cgi\" method=\"post\" autocomplete=\"off\">")
    supermicro_x12 = re.compile(b'<button type="button" class="trn login-btn" data-trn-key="LANG_LOGIN_LOGIN" id="login_word" name="Login" onclick="javascript: checkform\(this\)"></button>')
    asrock = re.compile(b"<script data-main=\"/app/main\" src=\"/source\.min\.js\"></script>", re.M)
    huawei = re.compile(b"<title>iBMC Login</title>")
    
    if dell8.search(page.content):
        ipmi_type = "dell8"
    if dell9.search(page.content):
        ipmi_type = "dell9"
    if supermicro_x8.search(page.content):
        ipmi_type = "sm8"
    if supermicro_x9.search(page.content):
        ipmi_type = "sm9_10_11_12"
    if supermicro_x12.search(page.content):
        ipmi_type = "sm9_10_11_12"
    if asrock.search(page.content):
        ipmi_type = "asrock"
    if huawei.search(page.content):
        ipmi_type = "huawei"
    return ipmi_type

def unknown_ipmi(reason="Can't detect IPMI type"):
    result = {
        "success": False,
        "content": None,
        "reason": reason,
        "type": None
    }
    return result

if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = 'ALL:@SECLEVEL=1'

    DETECT_TIMEOUT=5
    GET_TIMEOUT=10

    parser = argparse.ArgumentParser(description="Download IPMI console from supermicro/dell/asrock")
    parser.add_argument('-u', '--user', required=True, help="IPMI username")
    parser.add_argument('-p', '--password', required=True, help="IPMI user password")
    parser.add_argument('-H', '--host', required=True, help="IPMI host")
    args = parser.parse_args()

    try:
        ipmi = detect_ipmi(host=args.host)
    except requests.exceptions.ConnectTimeout:
        ipmi = 'Connect timeout'
    except requests.exceptions.ReadTimeout:
        ipmi = 'Read timeout'
    except requests.exceptions.SSLError:
        ipmi = 'SSL error'
    except Exception as e:
        ipmi = 'Unknown error'

    match ipmi:
        case "sm8":
            ipmi_console = supermicro_x8(host=args.host, user=args.user, password=args.password)
        case "sm9_10_11_12":
            ipmi_console = supermicro_x9_10_11_12(host=args.host, user=args.user, password=args.password)
        case "dell8":
            ipmi_console = dell_idrac8(host=args.host,user=args.user, password=args.password)
        case "dell9":
            ipmi_console = dell_idrac9(host=args.host,user=args.user, password=args.password)
        case "asrock":
            ipmi_console = asrock_java(host=args.host,user=args.user, password=args.password)
        case "huawei":
            ipmi_console = huawei(host=args.host,user=args.user, password=args.password)
        case "unknown":
            ipmi_console = unknown_ipmi()
        case _:
            ipmi_console = unknown_ipmi(ipmi)
    

    if ipmi_console['success']:
        print(ipmi_console['content'])
    else:
        sys.stderr.write(json.dumps(ipmi_console) + '\n')