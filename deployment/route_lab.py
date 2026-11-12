"""Linux-only real TLS/SSE/WebSocket continuity across atomic NAT and rollback."""
import base64,hashlib,http.client,http.server,json,os,socket,ssl,struct
import subprocess,tempfile,threading,time
from pathlib import Path
from urllib import request
from integration import free_port,head,AUTH,ADMIN

class HTTP6(http.server.ThreadingHTTPServer):
    address_family=socket.AF_INET6
    daemon_threads=True

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def log_message(self,*args):pass
    def do_GET(self):
        assert self.client_address[0]=='::1'
        if self.path=='/events':
            self.send_response(200);self.send_header('Content-Type','text/event-stream')
            self.send_header('Transfer-Encoding','chunked');self.end_headers()
            try:
                for n in range(100):
                    value=('data: '+str(n)+'\n\n').encode()
                    self.wfile.write(('%x\r\n'%len(value)).encode()+value+b'\r\n');self.wfile.flush();time.sleep(.1)
            except OSError:pass
        elif self.path=='/ws':
            key=self.headers['Sec-WebSocket-Key'];accept=base64.b64encode(hashlib.sha1((key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
            self.send_response(101);self.send_header('Upgrade','websocket');self.send_header('Connection','Upgrade');self.send_header('Sec-WebSocket-Accept',accept);self.end_headers()
            try:
                while True:
                    first=self.rfile.read(2)
                    if len(first)<2:return
                    size=first[1]&127;mask=self.rfile.read(4) if first[1]&128 else b''
                    value=self.rfile.read(size)
                    if mask:value=bytes(v^mask[i%4] for i,v in enumerate(value))
                    self.wfile.write(b'\x81'+bytes([len(value)])+value);self.wfile.flush()
            except OSError:pass
        else:
            value=b'fixed-ipv6-ok';self.send_response(200);self.send_header('Content-Length',str(len(value)));self.end_headers();self.wfile.write(value)

def run(binary):
    binary=Path(binary).resolve();processes=[];held=[];table='gost_recovery_lab_'+str(os.getpid())
    ports=[free_port() for _ in range(5)];logical,oldport,newport,oldapi,newapi=ports
    upstream=HTTP6(('::1',0),Handler);backendport=upstream.server_address[1]
    opener=request.build_opener(request.ProxyHandler({}))
    def api(port):
        req=request.Request('http://127.0.0.1:'+str(port)+'/config',headers={'Authorization':ADMIN})
        with opener.open(req,timeout=2) as r:return json.load(r)
    def route(target):
        text=f'''destroy table ip {table}
table ip {table} {{ chain output {{ type nat hook output priority -125; policy accept;
 ip daddr 127.0.0.1 tcp dport {logical} dnat to 127.0.0.1:{target}
}}
}}
'''
        checked=subprocess.run(['nft','-c','-f','-'],input=text,text=True,capture_output=True)
        assert checked.returncode==0, checked.stderr
        subprocess.run(['nft','-f','-'],input=text,text=True,check=True,capture_output=True)
    ctx=ssl._create_unverified_context()
    def connection(path):
        c=http.client.HTTPSConnection('127.0.0.1',logical,timeout=4,context=ctx)
        c.set_tunnel('::1',backendport,headers={'Proxy-Authorization':AUTH});c.request('GET',path);r=c.getresponse();held.append(c);return c,r
    def event(response):
        for _ in range(4):
            line=response.readline()
            if line.startswith(b'data:'):return line
        raise AssertionError('SSE stream ended')
    def websocket():
        s=socket.create_connection(('127.0.0.1',logical),4);s.settimeout(4)
        s.sendall(('CONNECT [::1]:'+str(backendport)+' HTTP/1.1\r\nHost: [::1]:'+str(backendport)+'\r\nProxy-Authorization: '+AUTH+'\r\n\r\n').encode());assert b' 200 ' in head(s)
        s=ctx.wrap_socket(s,server_hostname='fixture.local')
        s.sendall(b'GET /ws HTTP/1.1\r\nHost: fixture.local\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n');assert b' 101 ' in head(s);held.append(s);return s
    def ws_echo(s,text):
        value=text.encode();mask=b'abcd';payload=bytes(v^mask[i%4] for i,v in enumerate(value));s.sendall(b'\x81'+bytes([128|len(value)])+mask+payload)
        assert s.recv(2)==b'\x81'+bytes([len(value)])
        data=b''
        while len(data)<len(value):data+=s.recv(len(value)-len(data))
        assert data==value
    with tempfile.TemporaryDirectory(prefix='proxy-route-lab-') as d:
        root=Path(d)
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-subj','/CN=fixture.local','-days','1','-keyout',str(root/'key.pem'),'-out',str(root/'cert.pem')],check=True,capture_output=True)
        serverctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);serverctx.load_cert_chain(root/'cert.pem',root/'key.pem');upstream.socket=serverctx.wrap_socket(upstream.socket,server_side=True)
        thread=threading.Thread(target=upstream.serve_forever,daemon=True);thread.start()
        try:
            for name,port,adminport in [('old',oldport,oldapi),('new',newport,newapi)]:
                config={'api':{'addr':'127.0.0.1:'+str(adminport),'auth':{'username':'fixture-admin','password':'fixture-admin-password'}},'services':[{'name':'fixed','addr':'127.0.0.1:'+str(port),'interface':'::1','handler':{'type':'http','auth':{'username':'fixture','password':'fixture-password'}},'listener':{'type':'tcp'},'climiter':'fixed'}],'climiters':[{'name':'fixed','limits':['$ 1024']}],'log':{'level':'error'}}
                file=root/(name+'.json');file.write_text(json.dumps(config));log=(root/(name+'.log')).open('wb');p=subprocess.Popen([str(binary),'-C',str(file)],stdout=log,stderr=log);processes.append((p,log))
                deadline=time.monotonic()+10
                while True:
                    try:api(adminport);break
                    except Exception:
                        assert p.poll() is None and time.monotonic()<deadline;time.sleep(.1)
            route(oldport)
            old_sse,event_response=connection('/events');assert event_response.status==200;event(event_response)
            old_ws=websocket();ws_echo(old_ws,'before-switch')
            route(newport)
            event(event_response);ws_echo(old_ws,'after-switch')
            _,new_response=connection('/events');assert new_response.status==200;event(new_response)
            new_ws=websocket();ws_echo(new_ws,'new-generation')
            route(oldport)
            event(event_response);event(new_response);ws_echo(old_ws,'old-across-rollback');ws_echo(new_ws,'new-across-rollback')
            c,r=connection('/');assert r.status==200 and r.read()==b'fixed-ipv6-ok'
            assert all(p.poll() is None for p,_ in processes)
            result={'passed':True,'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'checks':['authenticated_fixed_ipv6','existing_tls_sse_and_websocket_survive_atomic_new_connection_switch','new_generation_serves_new_tls_sse_and_websocket','both_generations_existing_streams_survive_rollback','fresh_request_after_rollback_succeeds','neither_proxy_process_restarted']}
        finally:
            for c in held:
                try:c.close()
                except Exception:pass
            subprocess.run(['nft','delete','table','ip',table],capture_output=True)
            for p,log in processes:
                p.terminate()
                try:p.wait(timeout=5)
                except subprocess.TimeoutExpired:p.kill();p.wait()
                log.close()
            upstream.shutdown();upstream.server_close()
        return result

if __name__=='__main__':
    import sys
    result=run(sys.argv[1]);Path(sys.argv[2]).write_text(json.dumps(result,indent=2));print(json.dumps(result))
