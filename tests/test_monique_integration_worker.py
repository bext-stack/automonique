# SPDX-License-Identifier: Elastic-2.0
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[1] / 'tools'
sys.path.insert(0, str(TOOLS))
from monique_integration_worker import apply_patch, safe_path, provider_call, deliver, IntegrationError

class IntegrationWorkerTests(unittest.TestCase):
    def test_patch_preserves_assets_and_refuses_unsafe_or_binary_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'image.png').write_bytes(b'\x89PNG')
            entry=apply_patch(root,{'entry':'index.html','error':None,'files':[{'path':'index.html','content':'<h1>Report</h1>'}]})
            self.assertEqual(entry,'index.html');self.assertEqual((root/'image.png').read_bytes(),b'\x89PNG')
            for path in ['../secret','/secret','a/../secret','.env','a\\secret','a%2fsecret']:
                with self.assertRaises(IntegrationError):safe_path(path)
            with self.assertRaises(IntegrationError):apply_patch(root,{'entry':'a.pdf','files':[{'path':'a.pdf','content':'fake pdf'}]})
    def test_claude_is_tool_free_and_does_not_inherit_app_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);binary=root/'provider'
            binary.write_text('''#!/usr/bin/python3
import sys,os,json
assert sys.argv[sys.argv.index('--tools')+1]==''
assert '--safe-mode' in sys.argv and '--restricted' in sys.argv
assert 'SHARE_INGEST_SECRET' not in os.environ
json.loads(sys.stdin.read())
print(json.dumps({'type':'result','is_error':False,'structured_output':{'files':[{'path':'index.html','content':'Hello'}],'entry':'index.html','error':None,'summary':'Done'},'usage':{'input_tokens':12,'output_tokens':8}}))
''');binary.chmod(0o700)
            with patch.dict('os.environ',{'SHARE_INGEST_SECRET':'never-pass-this'}):
                value,usage=provider_call('claude',str(binary),root,root,'{}',threading.Event())
            self.assertEqual(value['entry'],'index.html');self.assertEqual(usage['input_tokens'],12)
    def test_codex_protocol_has_no_tools_and_returns_only_completed_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);binary=root/'provider'
            binary.write_text('''#!/usr/bin/python3
import sys,json
read=lambda:json.loads(sys.stdin.readline())
send=lambda x:print(json.dumps(x),flush=True)
assert 'features.shell_tool=false' in sys.argv
assert 'features.unified_exec=false' in sys.argv
assert 'mcp_servers={}' in sys.argv
assert read()['method']=='initialize';send({'id':1,'result':{}})
assert read()['method']=='initialized'
r=read();assert r['params']['ephemeral'] and r['params']['sandbox']=='read-only'
assert r['params']['dynamicTools']==[] and r['params']['environments']==[]
send({'id':2,'result':{'thread':{'id':'fixture'}}})
r=read();assert r['method']=='turn/start' and 'outputSchema' in r['params']
send({'method':'item/completed','params':{'item':{'type':'agentMessage','text':json.dumps({'files':[{'path':'x.txt','content':'Hello'}],'entry':'x.txt','error':None,'summary':'Done'})}}})
send({'method':'turn/completed','params':{'turn':{'status':'completed'}}})
''');binary.chmod(0o700)
            value,_=provider_call('codex',str(binary),root,root,'{}',threading.Event());self.assertEqual(value['entry'],'x.txt')
            binary.write_text(binary.read_text().replace("send({'method':'turn/completed','params':{'turn':{'status':'completed'}}})", ''))
            with self.assertRaises(IntegrationError):
                provider_call('codex',str(binary),root,root,'{}',threading.Event())
    def test_webhook_rejects_private_resolution_before_connecting(self):
        with patch('socket.getaddrinfo',return_value=[(2,1,6,'',('127.0.0.1',443))]):
            with self.assertRaisesRegex(IntegrationError,'webhook_address_refused'):
                deliver({'url':'https://app.example/events','body':'{}','headers':{}})

if __name__=='__main__':unittest.main()
