"""Exercise the updated runner against a temporary local HTTP contract double."""
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from json import dumps, loads
from threading import Thread
from unittest import TestCase, TestLoader, TextTestRunner
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

from core import Blocked, Context, Failure, Response
from run import META, PROFILE, REFERENCE, ROUTES, catalog_check, run_one

STAMP='2026-11-10T09:30:00.000Z'


def sandbox(sid, name, environments, status='ACTIVE'):
    return {'id':sid,'name':name,'projectId':'project1','version':1,'lifecycleStatus':status,
            'environments':environments,'allowedActions':['START','STOP','TERMINATE'],
            'isolation':None,'quota':None,'expiresAt':STAMP,'reclaimAt':None}


def environment(kind, status='SIMULATED_READY'):
    return {'id':'env-'+kind,'type':kind,'status':status,'flavor':{'id':'flavor1'},
            'imageId':'image1','readinessVerified':False}


class FakeAPI(BaseHTTPRequestHandler):
    def log_message(self,*_):
        pass

    def reply(self,status,payload=None,cookie=None):
        raw=dumps(payload,ensure_ascii=False).encode() if payload is not None else b''
        self.send_response(status)
        self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(raw)))
        if cookie:
            self.send_header('Set-Cookie',cookie)
        self.end_headers()
        self.wfile.write(raw)

    def ok(self,data,status=200,cookie=None):
        self.reply(status,{'data':data,'requestId':'self-test-ok'},cookie)

    def error(self,status,code):
        self.reply(status,{'code':code,'message':'模拟错误','requestId':'self-test-error'})

    def session(self):
        return self.headers.get('Cookie','').removeprefix('SANDBOX_SESSION=')

    def actor(self):
        return self.server.sessions.get(self.session())

    def token(self):
        return 'token-'+(self.session() or 'anonymous')

    def user(self,actor):
        return {'id':actor,'displayName':actor,'organizationId':'org-qa',
                'roles':['PLATFORM_ADMIN' if actor=='admin' else 'ANALYST'],
                'permissions':['sandbox:read'],'sessionExpiresAt':STAMP}

    def do_GET(self):
        url=urlsplit(self.path)
        path=url.path.removeprefix('/api/v1')
        query=parse_qs(url.query)
        if path=='/auth/csrf':
            self.ok({'csrfToken':self.token()})
        elif not self.actor():
            self.error(401,'UNAUTHENTICATED')
        elif path=='/me':
            self.ok(self.user(self.actor()))
        elif path=='/sandboxes':
            status=query.get('lifecycleStatus',[None])[0]
            name=query.get('keyword',[''])[0]
            items=[obj for obj in self.server.boxes.values()
                   if name in obj['name'] and
                   (obj['lifecycleStatus']==status if status else obj['lifecycleStatus']!='TERMINATED')]
            page=int(query.get('page',['1'])[0])
            size=int(query.get('pageSize',['20'])[0])
            self.ok({'items':items[(page-1)*size:page*size],'page':page,'pageSize':size,'total':len(items)})
        elif path.startswith(('/operations/','/sandboxes/operations/')):
            target=path.split('/')[-1]
            item=self.server.operations.get(target)
            if item:
                self.ok(item)
            else:
                self.error(404,'NOT_FOUND')
        elif path.startswith('/sandboxes/'):
            parts=path.split('/')
            item=self.server.boxes.get(parts[2])
            if not item:
                self.error(404,'NOT_FOUND')
            elif path.endswith('/member-events'):
                self.ok(self.server.member_events)
            elif path.endswith('/members'):
                self.ok(self.server.members)
            elif path.endswith('/status'):
                self.ok({**item,'sandboxId':item['id']})
            else:
                self.ok(item)
        else:
            self.error(404,'NOT_FOUND')

    def do_POST(self):
        path=self.path.removeprefix('/api/v1')
        size=int(self.headers.get('Content-Length','0'))
        body=loads(self.rfile.read(size)) if size else None
        if self.headers.get('X-CSRF-Token')!=self.token():
            self.error(403,'INVALID_CSRF')
            return
        if path in ('/auth/dev-login','/auth/login'):
            if body['password']!='self-test-pass':
                self.error(401,'INVALID_CREDENTIALS')
                return
            actor=body['username']
            session=str(uuid4())
            self.server.sessions[session]=actor
            self.ok(self.user(actor),cookie=f'SANDBOX_SESSION={session}; Path=/api/v1; HttpOnly')
            return
        if not self.actor():
            self.error(401,'UNAUTHENTICATED')
            return
        if path=='/auth/logout':
            self.server.sessions.pop(self.session(),None)
            self.ok(None,cookie='SANDBOX_SESSION=; Max-Age=0; Path=/api/v1')
            return
        key=self.headers.get('Idempotency-Key')
        if not key:
            self.error(400,'INVALID_ARGUMENT')
            return
        if key in self.server.replays:
            original_path,original_body,data,first_status=self.server.replays[key]
            if (path,body)!=(original_path,original_body):
                self.error(409,'BROKEN_CODE' if self.server.bad_conflict else 'IDEMPOTENCY_CONFLICT')
            else:
                self.ok(data,200 if first_status==201 else first_status)
            return
        if path=='/sandboxes':
            if not all(k in body for k in ('projectId','name','purpose','durationDays','environments')):
                self.error(400,'INVALID_ARGUMENT')
                return
            sid='new-'+str(len(self.server.boxes))
            item=sandbox(sid,body['name'],[environment(e['type']) for e in body['environments']])
            self.server.boxes[sid]=item
            self.remember(key,path,body,item,201)
        elif path.endswith('/actions'):
            parts=path.split('/')
            sid=parts[2]
            item=self.server.boxes[sid]
            if body.get('expectedVersion',item['version'])!=item['version']:
                self.error(409,'VERSION_CONFLICT')
                return
            touched=item['environments']
            single=len(parts)>4
            if single:
                touched=[e for e in touched if e['id']==parts[4]]
                if not touched:
                    self.error(404,'NOT_FOUND')
                    return
            for env in touched:
                env['status']='STOPPED' if body['action']=='STOP' else 'SIMULATED_READY'
            states={env['status'] for env in item['environments']}
            item['lifecycleStatus']='DEGRADED' if len(states)>1 else (
                'STOPPED' if 'STOPPED' in states else 'ACTIVE')
            item['version']+=1
            oid='operation-'+str(len(self.server.operations)+1)
            result={'id':oid,'sandboxId':sid,'status':'SUCCEEDED'}
            self.server.operations[oid]=result
            self.remember(key,path,body,touched[0] if single else result,202)
        elif path.endswith('/members'):
            mid='member-'+str(len(self.server.members)+1)
            member={'id':mid,**body}
            self.server.members.append(member)
            self.server.member_events.append({'memberId':mid,'action':'ADD'})
            self.remember(key,path,body,member,200)
        else:
            self.error(404,'NOT_FOUND')

    def do_DELETE(self):
        url=urlsplit(self.path)
        sid=url.path.split('/')[-1]
        item=self.server.boxes[sid]
        if self.headers.get('X-CSRF-Token')!=self.token():
            self.error(403,'INVALID_CSRF')
        elif int(parse_qs(url.query)['version'][0])!=item['version']:
            self.error(409,'VERSION_CONFLICT')
        else:
            self.server.deletions+=1
            item['lifecycleStatus']='TERMINATED'
            item['version']+=1
            for env in item['environments']:
                env['status']='TERMINATED'
            self.ok(item,202)

    def remember(self,key,path,body,data,status):
        self.server.replays[key]=(path,deepcopy(body),deepcopy(data),status)
        self.ok(data,status)


class SuiteTests(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server=ThreadingHTTPServer(('127.0.0.1',0),FakeAPI)
        cls.thread=Thread(target=cls.server.serve_forever,daemon=True)
        cls.thread.start()
        cls.config={
            'profile':PROFILE,'environment':'MOCK','timeout_seconds':2,
            'poll_interval_seconds':0.02,'poll_timeout_seconds':0.3,
            'base_url':f'http://127.0.0.1:{cls.server.server_address[1]}/api/v1',
            'fixtures':{
                'sandbox_owned':'owned','create_replay_http':200,'sandbox_new_name':'alternative',
                'account_permissions':{'A':['sandbox:read'],'M':['sandbox:read']},
                'logout_http':200,'terminate_http':202,'power_version_field':'expectedVersion',
                'sandbox_body':{'projectId':'project1','name':'fresh','purpose':'测试用途',
                                'durationDays':30,'environments':[{'type':'DEBUG'},{'type':'PRODUCTION'}]},
                'member_body':{'displayName':'测试成员','organization':'测试组','role':'EDITOR','reason':'联调用途'},
                'member_replay_http':200,'member_event_target_field':'memberId',
                'operation_sample':{'id':'existing','sandboxId':'owned'},
            },
        }
        cls.accounts={
            f'SANDBOX_QA_{role}_{field}':value
            for role,name in (('A','analyst'),('M','admin'),('OTHER','another'))
            for field,value in (('USER',name),('PASSWORD','self-test-pass'))
        }

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self):
        self.server.sessions={}
        self.server.replays={}
        self.server.bad_conflict=False
        self.server.deletions=0
        self.server.members=[]
        self.server.member_events=[]
        self.server.operations={'existing':{'id':'existing','sandboxId':'owned','status':'SUCCEEDED'}}
        self.server.boxes={'owned':sandbox('owned','existing',[environment('DEBUG'),environment('PRODUCTION')])}

    def execute(self,case_id,*,allow=False,config=None):
        with patch.dict('os.environ',self.accounts):
            return run_one(META[case_id],config or self.config,allow)

    def assert_result(self,case_id,status,**kwargs):
        result=self.execute(case_id,**kwargs)
        self.assertEqual(result['status'],status,result)
        return result

    def test_catalog_and_no_legacy_routes(self):
        catalog_check()
        self.assertEqual(len(META),135)
        self.assertNotIn('TC-12-01',META)
        ctx=Context(self.config,'self-test',ROUTES)
        ctx.require_route('POST','/sandboxes/sbox/environments/env/actions')
        ctx.require_route('GET','/sandboxes/operations/job')
        for method,path in (('POST','/approvals/a/decisions'),('POST','/sandboxes/sbox/member-requests')):
            with self.assertRaises(Blocked):
                ctx.require_route(method,path)

    def test_two_cookie_sessions_and_logout(self):
        result=self.assert_result('TC-V4-AUTH03-01','通过')
        self.assertNotIn('self-test-pass',dumps(result))
        self.assertNotIn('token-anonymous',dumps(result))
        self.assert_result('TC-V4-AUTH04-01','通过')

    def test_csrf_checks_prevent_side_effects(self):
        self.assert_result('TC-V4-AUTH01-01','需复核',allow=True)
        self.assertEqual(self.server.boxes['owned']['version'],1)
        self.assertEqual(len(self.server.operations),1)

    def test_direct_create_and_replay(self):
        result=self.assert_result('TC-V4-SBX04-04','需复核',allow=True)
        posts=[x['http'] for x in result['evidence'] if x['path']=='/sandboxes' and x['method']=='POST']
        self.assertEqual(posts,[201,200])
        self.assertEqual(len(self.server.boxes),2)

    def test_wrong_conflict_fails_with_request_id(self):
        self.server.bad_conflict=True
        result=self.assert_result('TC-V4-SBX04-05','失败',allow=True)
        self.assertEqual(result['evidence'][-1]['requestId'],'self-test-error')
        self.assertEqual(result['evidence'][-1]['code'],'BROKEN_CODE')

    def test_single_environment_isolation(self):
        result=self.assert_result('TC-V4-SBX06-01','通过',allow=True)
        self.assertIn(202,[x['http'] for x in result['evidence']])
        envs=self.server.boxes['owned']['environments']
        self.assertEqual([item['status'] for item in envs],['SIMULATED_READY','STOPPED'])
        self.assertEqual(self.server.boxes['owned']['lifecycleStatus'],'DEGRADED')

    def test_whole_power_uses_operation_and_version(self):
        self.server.boxes['stopped']=sandbox(
            'stopped','stopped',[environment('DEBUG','STOPPED'),environment('PRODUCTION','STOPPED')],'STOPPED')
        config={**self.config,'fixtures':{**self.config['fixtures'],'whole_power_samples':['owned','stopped']}}
        result=self.assert_result('TC-V4-SBX05-01','通过',allow=True,config=config)
        self.assertEqual(sum(e['path'].startswith('/operations/') for e in result['evidence']),4)
        self.assertEqual(self.server.boxes['owned']['lifecycleStatus'],'ACTIVE')
        self.assertEqual(self.server.boxes['stopped']['lifecycleStatus'],'STOPPED')

    def test_termination_uses_query_version(self):
        self.assert_result('TC-V4-SBX10-02','需复核',allow=True)
        self.assertEqual(self.server.deletions,0)
        self.assert_result('TC-V4-SBX10-01','需复核',allow=True)
        self.assertEqual(self.server.deletions,1)

    def test_reference_member_uses_new_route_and_event(self):
        config={**self.config,'profile':REFERENCE}
        result=self.assert_result('TC-V4-SBX12-03','通过',allow=True,config=config)
        self.assertTrue(any(e['path']=='/auth/login' for e in result['evidence']))
        self.assertEqual(len(self.server.members),1)
        self.assertEqual(len(self.server.member_events),1)

    def test_operation_profile_route_needs_confirmation(self):
        ref={**self.config,'profile':REFERENCE,'confirmed_cases':['TC-V4-OP01-01']}
        result=self.assert_result('TC-V4-OP01-01','需复核',config=ref)
        self.assertEqual(result['evidence'][-1]['path'],'/sandboxes/operations/existing')

    def test_guards_send_no_business_request(self):
        self.assertEqual(self.assert_result('TC-V4-SBX04-04','阻塞')['evidence'],[])
        partial={**self.config,'ready_interfaces':['AUTH01','AUTH02','SBX04']}
        result=self.assert_result('TC-V4-SBX04-04','阻塞',allow=True,config=partial)
        self.assertIn('SBX01',result['detail'])
        self.assertEqual(result['evidence'],[])
        missing={**self.config,'fixtures':{'sandbox_body':self.config['fixtures']['sandbox_body']}}
        self.assert_result('TC-V4-SBX04-04','阻塞',allow=True,config=missing)
        self.assertEqual(len(self.server.boxes),1)
        self.assertEqual(self.assert_result('TC-V4-SBX12-03','阻塞',allow=True)['evidence'],[])
        self.assertEqual(self.assert_result('TC-V4-SBX09-02','阻塞',allow=True)['evidence'],[])
        self.assert_result('TC-V4-SBX01-02','人工验证')
        self.assert_result('TC-V4-EXP07-01','阻塞')

    def test_response_contract_rejects_invalid_shapes(self):
        with self.assertRaises(Failure):
            Response(201,{'data':{'id':'x'}},b'').success(status=201)
        with self.assertRaises(Failure):
            Response(409,{'code':'STATE_CONFLICT','message':'冲突','requestId':'r','data':{}},b'').error(409)


def run_self_test():
    suite=TestLoader().loadTestsFromTestCase(SuiteTests)
    return 0 if TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
