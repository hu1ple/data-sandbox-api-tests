"""Focused verification of the suite against an in-process HTTP service."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from json import dumps, loads
from threading import Thread
from unittest import TestCase, TestLoader, TextTestRunner
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from core import Blocked, Context, Failure, Response
from run import META, ROUTES, catalog_check, run_one

STAMP = '2026-10-27T09:30:00.000Z'
SBX = {
    'id':'sbx-001','name':'QA沙箱','purpose':'测试用途','ownerId':'analyst',
    'projectId':'proj-001','approvalId':'ap-001','approvalStatus':'PENDING',
    'approvalVersion':1,'version':1,'lifecycleStatus':'REQUESTED',
    'createdAt':STAMP,'expiresAt':None,'environments':[],'allowedActions':[],
}


class FakeAPI(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def respond(self,status,data=None,cookie=None):
        raw = dumps(data,ensure_ascii=False).encode('utf-8') if data is not None else b''
        self.send_response(status)
        self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(raw)))
        if cookie:
            self.send_header('Set-Cookie',cookie)
        self.end_headers()
        if raw:
            self.wfile.write(raw)

    def ok(self,data,cookie=None):
        self.respond(200,{'data':data,'requestId':'test-success'},cookie)

    def error(self,status,code):
        self.respond(status,{'code':code,'message':'测试错误','requestId':'test-error'})

    def actor(self):
        cookie = self.headers.get('Cookie','')
        sid = cookie.removeprefix('sid=')
        return self.server.sessions.get(sid)

    def me(self,actor):
        role = 'ANALYST' if actor=='analyst' else 'PLATFORM_ADMIN'
        return {'id':actor,'organizationId':'qa','displayName':actor,'roles':[role],
                'permissions':[],'sessionExpiresAt':STAMP}

    def do_GET(self):
        url = urlsplit(self.path)
        path = url.path.removeprefix('/api/v1')
        query = parse_qs(url.query)
        if path=='/auth/csrf':
            self.ok({'csrfToken':'t-'+(self.actor() or 'anonymous')})
        elif not self.actor():
            self.error(401,'UNAUTHENTICATED')
        elif path=='/me':
            self.ok(self.me(self.actor()))
        elif path=='/sandboxes':
            self.page(list(self.server.sandboxes.values()),query)
        elif path=='/approvals':
            entries = [{'approvalId':item['approvalId']} for item in self.server.sandboxes.values()]
            self.page(entries,query)
        elif path.startswith('/sandboxes/'):
            if path.endswith('/other-sandbox') and self.actor()=='another':
                self.ok({'id':'other-sandbox'})
            else:
                self.error(404,'SANDBOX_NOT_FOUND')
        elif path.startswith('/tasks/'):
            self.error(404,'BROKEN_CODE' if self.server.bad_task_code else 'TASK_NOT_FOUND')
        else:
            self.error(404,'MOCK_UNKNOWN_PATH')

    def page(self,items,query):
        page = int(query.get('page',['1'])[0])
        size = int(query.get('pageSize',['20'])[0])
        self.ok({'items':items[(page-1)*size:page*size],'page':page,'pageSize':size,'total':len(items)})

    def do_POST(self):
        path = self.path.removeprefix('/api/v1')
        size = int(self.headers.get('Content-Length','0'))
        body = loads(self.rfile.read(size)) if size else None
        actor = self.actor()
        if self.headers.get('X-CSRF-Token')!='t-'+(actor or 'anonymous'):
            self.error(403,'INVALID_CSRF')
        elif path=='/auth/dev-login':
            actor = body['username']
            if actor not in ('analyst','admin','another') or body['password']!='qa-pass':
                self.error(401,'INVALID_CREDENTIALS')
                return
            sid = 'session-'+actor
            self.server.sessions[sid] = actor
            self.ok(self.me(actor),f'sid={sid}; Path=/api/v1; HttpOnly')
        elif path=='/auth/logout' and actor:
            self.server.sessions.pop('session-'+actor,None)
            self.respond(204,cookie='sid=; Max-Age=0; Path=/api/v1; HttpOnly')
        elif path=='/sandboxes' and actor:
            key = self.headers.get('Idempotency-Key')
            if key not in self.server.sandboxes:
                self.server.sandboxes[key] = {**SBX,'projectId':body['projectId'],'name':body['name']}
            self.ok(self.server.sandboxes[key])
        else:
            self.error(404,'MOCK_UNKNOWN_PATH')


class SuiteTests(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1',0),FakeAPI)
        cls.thread = Thread(target=cls.server.serve_forever,daemon=True)
        cls.thread.start()
        cls.cfg = {
            'base_url':f'http://127.0.0.1:{cls.server.server_address[1]}/api/v1',
            'timeout_seconds':3,'environment':'MOCK','fixtures':{
                'sandbox_other':'other-sandbox',
                'sandbox_body':{'projectId':'proj-001','name':'QA沙箱','purpose':'测试用途',
                                'durationDays':30,'environments':[]},
            },
        }
        cls.env = {
            f'SANDBOX_QA_{role}_{field}': value
            for role,name in [('A','analyst'),('M','admin'),('OTHER','another')]
            for field,value in [('USER',name),('PASSWORD','qa-pass')]
        }

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)

    def setUp(self):
        self.server.sessions = {}
        self.server.sandboxes = {}
        self.server.bad_task_code = False

    def run_case(self, case_id, allow=False, cfg=None):
        with patch.dict('os.environ',self.env):
            return run_one(META[case_id],cfg or self.cfg,allow)

    def test_index_and_route_patterns(self):
        catalog_check()
        ctx = Context(self.cfg,'test',ROUTES)
        ctx.require_route('GET','/sandboxes/sbx-001')
        ctx.require_route('POST','/sandboxes/sbx-001/environments/e1/actions')
        with self.assertRaises(Blocked):
            ctx.require_route('DELETE','/sandboxes/sbx-001')

    def test_csrf_cookie_login(self):
        result = self.run_case('TC-01-01')
        self.assertEqual(result['status'],'通过',result)
        self.assertEqual([x['http'] for x in result['evidence']],[200,200,200])
        serialized = dumps(result)
        self.assertNotIn('qa-pass',serialized)
        self.assertNotIn('session-analyst',serialized)
        self.assertNotIn('t-anonymous',serialized)

    def test_logout_checks_old_cookie(self):
        result = self.run_case('TC-03-01')
        self.assertEqual(result['status'],'需复核',result)
        self.assertEqual([x['http'] for x in result['evidence'][-3:]],[204,401,401])

    def test_foreign_sandbox_has_owner_and_is_inaccessible(self):
        result = self.run_case('TC-10-02')
        self.assertEqual(result['status'],'通过',result)
        self.assertEqual(result['evidence'][-1]['code'],'SANDBOX_NOT_FOUND')

    def test_write_guard_and_replay(self):
        denied = self.run_case('TC-12-08')
        self.assertEqual(denied['status'],'阻塞')
        self.assertEqual(denied['evidence'],[])
        result = self.run_case('TC-12-08',allow=True)
        self.assertEqual(result['status'],'通过',result)
        self.assertEqual(len(self.server.sandboxes),1)

    def test_followup_dependency_checked_before_write(self):
        result = self.run_case('TC-12-08',allow=True,cfg={**self.cfg,'ready_interfaces':[1,2,9,12]})
        self.assertEqual(result['status'],'阻塞')
        self.assertIn('API-29',result['detail'])
        self.assertEqual(result['evidence'],[])
        self.assertEqual(self.server.sandboxes,{})

    def test_missing_confirmation_prevents_writes(self):
        result = self.run_case('TC-27-04',allow=True)
        self.assertEqual(result['status'],'阻塞')
        self.assertIn('default_days_http',result['detail'])
        self.assertEqual(result['evidence'],[])

    def test_bad_business_code_fails_not_blocks(self):
        self.server.bad_task_code = True
        result = self.run_case('TC-19-02')
        self.assertEqual(result['status'],'失败',result)
        self.assertEqual(result['evidence'][-1]['requestId'],'test-error')

    def test_readiness_and_external_block(self):
        result = self.run_case('TC-10-02',cfg={**self.cfg,'ready_interfaces':[1,2]})
        self.assertEqual(result['status'],'阻塞',result)
        self.assertIn('API-10',result['detail'])
        self.assertEqual(self.run_case('TC-33-02')['status'],'阻塞')
        self.assertEqual(self.run_case('TC-33-01')['status'],'人工验证')

    def test_response_contract_rejects_invalid_shapes(self):
        with self.assertRaises(Failure):
            Response(200,{'data':{'items':[]}},b'').success()
        with self.assertRaises(Failure):
            Response(409,{'code':'VERSION_CONFLICT','message':'冲突','requestId':'r','data':{}},b'').error(409)
        with self.assertRaises(Failure):
            Response(204,None,b'extra').empty_success()


def run_self_test():
    suite = TestLoader().loadTestsFromTestCase(SuiteTests)
    result = TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1
