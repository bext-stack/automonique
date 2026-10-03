#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0
"""Publish versioned report bundles to Share, private by default.

Uses the existing private share/share.conf; never prints service credentials.
All providers can invoke this tool. Run/conversation context is inherited from
Monique's worker environment, or supplied explicitly for an interactive task.
"""
import argparse
import base64
import html
import hashlib
import json
import mimetypes
import os
from pathlib import Path
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request


def folded_base64(data):
    encoded = base64.b64encode(data).decode()
    return '\n'.join(encoded[i:i+6] for i in range(0, len(encoded), 6))


class ArtifactClient:
    def __init__(self, state):
        path = Path(state) / 'share/share.conf'
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_size > 16384:
            raise ValueError('Artifact configuration must be a private regular file.')
        cfg = dict(line.split('=', 1) for line in path.read_text().splitlines() if '=' in line)
        self.base = cfg['public_base'].rstrip('/')
        url = urllib.parse.urlsplit(self.base)
        if url.scheme != 'https' or not url.hostname or url.username or url.password or url.path or url.query or url.fragment:
            raise ValueError('Artifact service must use an HTTPS origin.')
        self.secret = cfg['secret']
        if len(self.secret) < 32 or any(c.isspace() for c in self.secret):
            raise ValueError('Invalid artifact service credential.')
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def call(self, action, **args):
        req = urllib.request.Request(self.base + '/api/artifacts', data=json.dumps({'action': action, **args}).encode(), headers={'Content-Type': 'application/json', 'User-Agent': 'MoniqueArtifact/1.0', 'x-share-ingest-secret': self.secret})
        try:
            with self.opener.open(req, timeout=60) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            try:
                code = json.loads(error.read(4096)).get('error', 'request_failed')
            except (ValueError, AttributeError):
                code = 'request_failed'
            raise ValueError('Artifact service refused the request: ' + str(code)) from None


def bundle_files(source):
    source = Path(source)
    if source.is_symlink():
        raise ValueError('Symlinks are not accepted.')
    root = source if source.is_dir() else source.parent
    candidates = sorted(source.rglob('*')) if source.is_dir() else [source]
    files = []
    total = 0
    for path in candidates:
        relative = path.relative_to(root)
        if any(part.startswith('.') for part in relative.parts):
            continue
        if path.is_symlink():
            raise ValueError('Bundle contains a symlink: ' + str(relative))
        if path.is_dir():
            continue
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > 128 * 1024 * 1024:
            raise ValueError('Unsupported or oversized file: ' + str(relative))
        name = relative.as_posix()
        if any(c in name for c in '\\?#:%') or len(name) > 240:
            raise ValueError('Unsupported filename: ' + name)
        total += info.st_size
        files.append((path, {'path': name, 'bytes': info.st_size, 'type': mimetypes.guess_type(name)[0] or 'application/octet-stream'}))
    if not files or len(files) > 400 or total > 512 * 1024 * 1024:
        raise ValueError('Bundle must contain 1–400 files and at most 512 MiB.')
    return files


def publish(client, args):
    files = bundle_files(args.path)
    entry = args.entry or next((m['path'] for _, m in files if m['path'] == 'index.html'), files[0][1]['path'])
    context = {'title': args.title or Path(args.path).name, 'description': args.description, 'project': args.project, 'issue_url': args.issue or os.environ.get('MONIQUE_ARTIFACT_ISSUE_URL', ''), 'run_id': args.run_id or os.environ.get('MONIQUE_ARTIFACT_RUN_ID', ''), 'conversation_id': args.conversation or os.environ.get('MONIQUE_ARTIFACT_CONVERSATION_ID', ''), 'agent': args.agent or os.environ.get('MONIQUE_ARTIFACT_AGENT', '')}
    if args.artifact_id:
        a = client.call('get', id=args.artifact_id)['artifact']
        context = {'id': a['id'], 'revision': a['revision']}
    draft = client.call('begin', **context, entry=entry, note=args.note, files=[m for _, m in files])
    for path, meta in files:
        # O_NOFOLLOW protects against files being replaced with links mid-upload.
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size != meta['bytes']:
                raise ValueError('Bundle changed during publication.')
            index = 0
            while True:
                data = stream.read(draft['chunk_bytes'])
                if not data:
                    break
                client.call('chunk', draft_id=draft['draft_id'], path=meta['path'], index=index, content_base64=folded_base64(data))
                index += 1
            after = os.fstat(stream.fileno())
            if before.st_mtime_ns != after.st_mtime_ns or before.st_size != after.st_size:
                raise ValueError('Bundle changed during publication.')
    artifact = client.call('commit', draft_id=draft['draft_id'])['artifact']
    if args.public and artifact['visibility'] != 'public':
        artifact = client.call('update', id=artifact['id'], revision=artifact['revision'], visibility='public')['artifact']
    return artifact


def download(client, artifact_id, destination, version=None):
    a = client.call('get', id=artifact_id)['artifact']
    v = next((v for v in a['versions'] if v['number'] == version), None) if version else a['versions'][-1]
    if not v:
        raise ValueError('Version not found.')
    root = Path(destination)
    if root.exists():
        raise ValueError('Download destination must not already exist.')
    root.mkdir(parents=True, mode=0o700)
    for file in v['files']:
        relative = Path(file['path'])
        if relative.is_absolute() or any(p in ('..', '.') or p.startswith('.') for p in relative.parts):
            raise ValueError('Unsafe file path in manifest.')
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        size = 0
        with target.open('xb') as output:
            for index in range(file['chunks']):
                chunk = client.call('read', id=a['id'], version=v['number'], path=file['path'], index=index)
                data = base64.b64decode(chunk['content_base64'], validate=True)
                if len(data) != chunk['bytes'] or hashlib.sha256(data).hexdigest() != chunk['sha256']:
                    raise ValueError('Downloaded chunk did not match its digest.')
                output.write(data); size += len(data)
        if size != file['bytes']:
            raise ValueError('Downloaded file is incomplete.')
    return a


def report_template(path, title):
    target = Path(path)
    if target.exists():
        raise ValueError('Template destination already exists.')
    title = html.escape(title)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text('''<!doctype html><html lang="fr"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>''' + title + '''</title><style>body{margin:0;background:#f5f5f2;color:#152137;font:16px/1.6 system-ui}main{max-width:1040px;margin:auto;padding:50px 24px}header{background:#142138;color:white;padding:32px;border-radius:16px}small{color:#c5b663;text-transform:uppercase;letter-spacing:.15em}h1{font-size:clamp(28px,5vw,48px);line-height:1.12}section{background:white;padding:28px;margin:20px 0;border:1px solid #e4e5e7;border-radius:12px}img{max-width:100%;border-radius:8px}a{color:#284a80}table{border-collapse:collapse;width:100%}td,th{text-align:left;padding:10px;border-bottom:1px solid #ddd}</style><main><header><small>Webdesign29 · compte rendu</small><h1>''' + title + '''</h1><p>Résumé concret du résultat livré.</p></header><section><h2>Ce qui a changé</h2><p>Décrivez les changements observables et leur intérêt pour le client.</p></section><section><h2>Vérifications</h2><table><tr><th>Contrôle</th><th>Résultat observé</th></tr><tr><td>À compléter</td><td>À compléter avec les preuves réelles</td></tr></table></section><section><h2>Captures et documents</h2><p>Ajoutez les ressources dans ce dossier et utilisez des liens relatifs.</p></section><section><h2>Prochaines étapes</h2><p>Décisions attendues, limites et travaux restant à réaliser.</p></section></main></html>''')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state-dir', default=os.environ.get('AUTOMONIQUE_STATE_DIR') or str(Path(os.environ.get('XDG_STATE_HOME', Path.home() / '.local/state')) / 'automonique'))
    commands = parser.add_subparsers(dest='command', required=True)
    pub = commands.add_parser('publish')
    pub.add_argument('path')
    for name in ['title', 'description', 'project', 'issue', 'run-id', 'conversation', 'agent', 'artifact-id', 'entry', 'note']:
        pub.add_argument('--' + name, default='')
    pub.add_argument('--public', action='store_true', help='Explicitly make all versions accessible to anyone with the link.')
    commands.add_parser('list')
    get = commands.add_parser('get'); get.add_argument('id')
    dl = commands.add_parser('download'); dl.add_argument('id'); dl.add_argument('destination'); dl.add_argument('--version', type=int)
    visibility = commands.add_parser('visibility'); visibility.add_argument('id'); visibility.add_argument('visibility', choices=['private', 'public'])
    template = commands.add_parser('template'); template.add_argument('path'); template.add_argument('--title', required=True)
    args = parser.parse_args()
    try:
        if args.command == 'template':
            report_template(args.path, args.title)
            print('Report template created. Replace placeholders with verified results before publication.')
            return
        client = ArtifactClient(args.state_dir)
        if args.command == 'publish':
            a = publish(client, args)
            print('MONIQUE_ARTIFACT_ID: ' + a['id'])
            print('MONIQUE_ARTIFACT_URL: ' + client.base + a['url'])
            print('MONIQUE_ARTIFACT_VERSION: ' + str(a['version_count']))
            print('MONIQUE_ARTIFACT_VISIBILITY: ' + a['visibility'])
        elif args.command == 'download':
            a = download(client, args.id, args.destination, args.version)
            print('Downloaded artifact ' + a['id'] + ' into ' + args.destination)
        elif args.command == 'visibility':
            a = client.call('get', id=args.id)['artifact']
            print(json.dumps(client.call('update', id=args.id, revision=a['revision'], visibility=args.visibility)))
        else:
            print(json.dumps(client.call(args.command, **({'id': args.id} if args.command == 'get' else {}))))
    except (ValueError, OSError, KeyError, urllib.error.URLError) as error:
        # Never dump a request, config, or exception URL which might hold credentials.
        print('Artifact operation failed: ' + (str(error) if isinstance(error, ValueError) else type(error).__name__), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
