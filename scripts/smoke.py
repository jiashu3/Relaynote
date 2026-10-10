#!/usr/bin/env python3
"""Exercise only a local Relaynote binary with synthetic loopback messages."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('binary', type=Path)
a = p.parse_args()
binary = str(a.binary.resolve())
with tempfile.TemporaryDirectory(prefix='relaynote-smoke-') as directory:
    root = Path(directory)
    os.chmod(root, 0o700)
    db = str(root/'hub.db')
    tokens = {peer: str(root/(peer+'.token')) for peer in ('A', 'B')}
    def cli(*args, check=True):
        return subprocess.run([binary, '--db', db, *args], check=check, capture_output=True, text=True, timeout=20)
    for peer, other in (('A','B'), ('B','A')):
        cli('provision', '--peer', peer, '--allow', other, '--out', tokens[peer])
    def start():
        proc = subprocess.Popen([binary, '--db', db, 'serve', '--listen', '127.0.0.1:0'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        # Server prints only a local synthetic endpoint. No external services.
        return proc, json.loads(proc.stdout.readline())['listening']
    proc = None
    try:
        proc, base = start()
        def node(peer, *args):
            result = cli('--url', base, '--token-file', tokens[peer], '--outbox', str(root/(peer+'-outbox.db')), *args)
            return json.loads(result.stdout) if result.stdout.strip() else None
        message = node('A','send','--to','B','--body','synthetic ping','--client-id','roundtrip')
        claim = node('B','claim','--lease','1')['messages'][0]
        proc.kill(); proc.communicate(timeout=10)
        time.sleep(1.05)
        proc, base = start()
        recovered = node('B','claim')['messages'][0]
        assert recovered['id']==claim['id'] and recovered['attempts']==2
        assert recovered['receipt']!=claim['receipt']
        repeated = node('A','send','--to','B','--body','synthetic ping','--client-id','roundtrip')
        assert repeated['id']==message['id']
        node('B','ack','--id',recovered['id'],'--receipt='+recovered['receipt'])
        reply = node('B','reply','--parent',message['id'],'--body','synthetic pong','--client-id','reply')
        received = node('A','claim')['messages'][0]
        assert received['id']==reply['id'] and received['thread_id']==message['thread_id']
        node('A','ack','--id',received['id'],'--receipt='+received['receipt'])
        assert node('B','get','--id',reply['id'])['state']=='acknowledged'
        assert received['agent_awakened']=='unverified'
        print('PASS: compiled-binary A→B→A, forced process kill, durable restart, lease redelivery, idempotency and ACK')
    finally:
        if proc is not None:
            proc.terminate(); proc.communicate(timeout=10)
