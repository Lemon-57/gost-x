"""Synthetic local proxy overflow, live reload and stream continuity checks."""
import argparse, base64, hashlib, http.client, json, os, select, socket
import subprocess, tempfile, threading, time
from pathlib import Path
from urllib import request

AUTH = 'Basic ' + base64.b64encode(b'fixture:fixture-password').decode()
ADMIN = 'Basic ' + base64.b64encode(b'fixture-admin:fixture-admin-password').decode()

def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def head(sock):
    data = b''
    while b'\r\n\r\n' not in data:
        chunk = sock.recv(1)
        if not chunk:
            raise ConnectionResetError('connection ended before HTTP headers')
        data += chunk
        assert len(data) < 8192
    return data

def fixture(listener, stop):
    # A single select loop holds many idle tunnels without a thread per socket.
    peers = []
    while not stop.is_set():
        ready, _, _ = select.select([listener] + peers, [], [], .1)
        for s in ready:
            if s is listener:
                c, _ = listener.accept()
                c.setblocking(False)
                peers.append(c)
            else:
                try:
                    data = s.recv(8192)
                    if not data:
                        peers.remove(s); s.close(); continue
                    s.sendall(data)
                except OSError:
                    peers.remove(s); s.close()
    for s in peers:
        s.close()

def run(binary):
    if os.name != 'nt':
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        resource.setrlimit(resource.RLIMIT_NOFILE, (min(hard, max(8192, soft)), hard))
    binary = Path(binary).resolve()
    api_port, proxy_port, capacity_port = [free_port() for _ in range(3)]
    upstream = socket.socket(socket.AF_INET6)
    upstream.bind(('::1', 0)); upstream.listen(2048)
    target_port = upstream.getsockname()[1]
    stop = threading.Event()
    # Windows select() has an fd limit; poll-based selectors work on Linux.
    def backend():
        import selectors
        sel = selectors.DefaultSelector(); sel.register(upstream, 1)
        try:
            while not stop.is_set():
                for key, _ in sel.select(.1):
                    s = key.fileobj
                    if s is upstream:
                        c, _ = s.accept(); c.setblocking(False); sel.register(c, 1)
                    else:
                        try:
                            data = s.recv(8192)
                            if not data: sel.unregister(s); s.close()
                            else: s.sendall(data)
                        except OSError:
                            sel.unregister(s); s.close()
        finally:
            for key in list(sel.get_map().values()):
                if key.fileobj is not upstream: key.fileobj.close()
            sel.close()
    thread = threading.Thread(target=backend, daemon=True); thread.start()
    def service(name, port):
        return {'name': name, 'addr': '127.0.0.1:' + str(port),
                'interface': '::1', 'handler': {'type': 'http',
                'auth': {'username': 'fixture', 'password': 'fixture-password'}},
                'listener': {'type': 'tcp'}, 'climiter': name}
    cfg = {'api': {'addr': '127.0.0.1:' + str(api_port),
                  'auth': {'username': 'fixture-admin', 'password': 'fixture-admin-password'}},
           'services': [service('overflow', proxy_port), service('capacity', capacity_port)],
           'climiters': [{'name': 'overflow', 'limits': ['$ 2']},
                        {'name': 'capacity', 'limits': ['$ 1024']}], 'log': {'level': 'error'}}
    opener = request.build_opener(request.ProxyHandler({}))
    def api(path='/config', method='GET', body=None):
        req = request.Request('http://127.0.0.1:' + str(api_port) + path,
                              method=method, headers={'Authorization': ADMIN,
                              'Content-Type': 'application/json'},
                              data=None if body is None else json.dumps(body).encode())
        with opener.open(req, timeout=3) as r: return json.load(r)
    def tunnel(port=proxy_port, authorization=AUTH):
        s = socket.create_connection(('127.0.0.1', port), 3); s.settimeout(3)
        s.sendall(('CONNECT [::1]:'+str(target_port)+' HTTP/1.1\r\nHost: [::1]:'+str(target_port)+'\r\nProxy-Authorization: '+authorization+'\r\n\r\n').encode())
        try:
            assert b' 200 ' in head(s).split(b'\r\n')[0]
            return s
        except BaseException:
            s.close(); raise
    def echo(s, value):
        s.sendall(value); data=b''
        while len(data)<len(value):
            part=s.recv(len(value)-len(data))
            if not part: raise ConnectionResetError('held tunnel ended')
            data+=part
        assert data==value
    held=[]; results=[]
    with tempfile.TemporaryDirectory(prefix='proxy-overflow-') as directory:
        root=Path(directory); path=root/'config.json'; path.write_text(json.dumps(cfg))
        with (root/'proxy.log').open('wb') as log:
            process=subprocess.Popen([str(binary),'-C',str(path)],stdout=log,stderr=log)
            try:
                deadline=time.monotonic()+15
                while True:
                    try: api(); break
                    except Exception:
                        if process.poll() is not None: raise RuntimeError('local proxy exited')
                        if time.monotonic()>deadline: raise
                        time.sleep(.1)
                first=tunnel(); second=tunnel(); held.extend([first,second])
                for _ in range(8):
                    try:
                        s=tunnel(); s.close(); raise AssertionError('limit was bypassed')
                    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError): pass
                echo(first,b'data-before-limit-recovery'); echo(second,b'other-held-request')
                assert next(v for v in api()['services'] if v['name']=='overflow')['status']['state']=='ready'
                results.append('overflow_rejects_only_new_connections_and_preserves_held_tunnels')
                first.close(); held.remove(first); time.sleep(.15)
                recovered=tunnel(); held.append(recovered); echo(recovered,b'automatic-accept-recovery')
                results.append('capacity_release_allows_new_tunnels_without_restart')
                api('/config/climiters/overflow','PUT',{'name':'overflow','limits':['$ 1024']})
                echo(second,b'held-stream-across-budget-update'); echo(recovered,b'held-websocket-across-budget-update')
                new=tunnel(); held.append(new); echo(new,b'new-connection-after-budget-update')
                results.append('live_budget_update_to_1024_preserves_existing_tunnels')
                try:
                    s=tunnel(capacity_port,'Basic '+base64.b64encode(b'fixture:wrong').decode());s.close()
                    raise AssertionError('invalid credentials accepted')
                except AssertionError as e:
                    if str(e)=='invalid credentials accepted':raise
                results.append('authentication_is_preserved')
                # Exercise the actual 1024 limit on Linux, where selectors have
                # no Windows select fd-set limit. Windows still checks overflow.
                if os.name!='nt':
                    capacity=[tunnel(capacity_port) for _ in range(1024)];held.extend(capacity)
                    try:
                        s=tunnel(capacity_port);s.close();raise AssertionError('1025th connection accepted')
                    except (ConnectionResetError,ConnectionAbortedError,BrokenPipeError):pass
                    echo(capacity[0],b'first-of-1024');echo(capacity[-1],b'last-of-1024')
                    capacity[0].close();held.remove(capacity[0]);time.sleep(.15)
                    replacement=tunnel(capacity_port);held.append(replacement);echo(replacement,b'recovery-at-1024')
                    results.append('1024_held_connections_1025th_rejected_and_capacity_recovers')
                assert process.poll() is None
                result={'passed':True,'checks':results,'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest()}
            finally:
                for s in held:s.close()
                process.terminate()
                try:process.wait(timeout=8)
                except subprocess.TimeoutExpired:process.kill();process.wait()
                stop.set();thread.join(3);upstream.close()
        return result

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('binary');p.add_argument('--output');args=p.parse_args()
    result=run(args.binary)
    if args.output:Path(args.output).write_text(json.dumps(result,indent=2))
    print(json.dumps(result))
