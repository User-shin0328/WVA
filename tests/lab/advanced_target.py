"""Owned fixtures for policies, cleanup, browser boundaries and timing SQL.

SQLite queries execute against in-memory fixture rows; no production data exists.
"""
import argparse
import asyncio
import html
import json
import sqlite3
import time
import uuid
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, StreamingResponse
import uvicorn


def create_app(external_url='http://127.0.0.1:1/sink'):
    app=FastAPI(docs_url=None,openapi_url=None)
    app.state.hits=[];app.state.stored={};app.state.login_tokens={};app.state.sessions={}
    @app.middleware('http')
    async def hits(request,call_next):
        app.state.hits.append((request.method,request.url.path))
        return await call_next(request)

    @app.get('/',response_class=HTMLResponse)
    async def root():return '<h1>WVA owned advanced fixture</h1>'

    def query(value, safe=False):
        with sqlite3.connect(':memory:') as db:
            db.executescript("CREATE TABLE items(id INTEGER,value TEXT);INSERT INTO items VALUES(1,'fixture-item');")
            db.create_function('wva_delay',1,lambda seconds:time.sleep(min(max(float(seconds),0),.75)) or 0)
            if safe:return db.execute('SELECT value FROM items WHERE id=?',(value,)).fetchall()
            return db.execute('SELECT value FROM items WHERE id=('+value+')').fetchall()

    @app.get('/sql',response_class=HTMLResponse)
    @app.get('/safe-sql',response_class=HTMLResponse)
    async def sql(request:Request,id:str='1'):
        try:rows=await asyncio.to_thread(query,id,request.url.path=='/safe-sql')
        except sqlite3.Error:return HTMLResponse('SQLITE_ERROR: test query rejected',status_code=500)
        return '<form><input name="id" value="1"></form><pre>'+html.escape(json.dumps(rows))+'</pre>'

    @app.get('/unstable',response_class=HTMLResponse)
    async def unstable(id:str='1'):return '<form><input name="id"></form><p>'+uuid.uuid4().hex+'</p>'

    @app.get('/waf',response_class=HTMLResponse)
    async def waf(id:str='1'):
        if id!='1':return HTMLResponse('Request blocked by test policy',status_code=403)
        return '<form><input name="id"></form><p>baseline</p>'

    @app.get('/db-error',response_class=HTMLResponse)
    async def error(id:str='1'):
        if id!='1':return HTMLResponse('SQLSTATE[42000] test database error',status_code=500)
        return '<form><input name="id"></form><p>baseline</p>'

    @app.get('/reflected',response_class=HTMLResponse)
    @app.get('/safe-reflected',response_class=HTMLResponse)
    @app.get('/csp-reflected',response_class=HTMLResponse)
    async def reflected(request:Request,name:str='baseline'):
        text=html.escape(name) if request.url.path=='/safe-reflected' else name
        headers={'Content-Security-Policy':"default-src 'self'; script-src 'none'"} if request.url.path=='/csp-reflected' else {}
        return HTMLResponse('<form><input name="name"></form><div>'+text+'</div>',headers=headers)

    @app.get('/spa/',response_class=HTMLResponse)
    async def spa():return '<div id="result"></div><script src="/spa/app.js"></script>'
    @app.get('/spa/app.js')
    async def javascript():
        return PlainTextResponse("document.getElementById('result').innerHTML=new URLSearchParams(location.hash.split('?')[1]||'').get('q')||'';",media_type='text/javascript')

    @app.get('/boundary/',response_class=HTMLResponse)
    async def boundary(name:str='baseline'):
        return f'<img src="{external_url}"><img src="/outside"><script>fetch("/boundary/change",{{method:"POST"}});new WebSocket("ws://"+location.host+"/boundary/ws")</script>{name}'
    @app.get('/outside')
    async def outside():return {'outside':True}
    @app.post('/boundary/change')
    async def change():return {'changed':True}
    @app.websocket('/boundary/ws')
    async def websocket(ws):
        app.state.hits.append(('WS','/boundary/ws'));await ws.accept();await ws.close()

    @app.get('/oversize')
    async def oversized():
        async def chunks():
            for _ in range(100):yield b'x'*10000
        return StreamingResponse(chunks(),media_type='text/plain')

    @app.get('/login',response_class=HTMLResponse)
    async def login_get():
        sid=uuid.uuid4().hex;token=uuid.uuid4().hex;app.state.login_tokens[sid]=token
        response=HTMLResponse(f'<form method="post"><input name="username"><input name="password" type="password"><input type="hidden" name="csrf" value="{token}"></form>')
        response.set_cookie('login_sid',sid,httponly=True);return response
    @app.post('/login')
    async def login_post(request:Request):
        from urllib.parse import parse_qs
        fields={k:v[0] for k,v in parse_qs((await request.body()).decode()).items()}
        alias=fields.get('username')
        if fields.get('csrf')!=app.state.login_tokens.get(request.cookies.get('login_sid')) or fields.get('password')!='local-only-'+str(alias):return JSONResponse({},status_code=403)
        session='wva-session-'+uuid.uuid4().hex;app.state.sessions[session]=alias
        response=JSONResponse({'authenticated':True});response.set_cookie('session',session,httponly=True);return response
    @app.get('/object/{mode}')
    async def object_read(request:Request,mode:str):
        alias=app.state.sessions.get(request.cookies.get('session'))
        if mode!='vulnerable' and alias!='A':return JSONResponse({},status_code=403)
        return {'private_record':'fixture-account-A'}
    @app.get('/role/{mode}')
    async def role_read(request:Request,mode:str):
        alias=app.state.sessions.get(request.cookies.get('session'))
        if mode!='vulnerable' and alias!='admin':return JSONResponse({},status_code=403)
        return {'private_record':'fixture-admin-only'}

    @app.get('/timing',response_class=HTMLResponse)
    async def timing(id:str='1'):
        try:rows=await asyncio.to_thread(query,id)
        except sqlite3.Error:return HTMLResponse('SQLITE_ERROR',status_code=500)
        return json.dumps(rows)

    @app.get('/stored/write',response_class=HTMLResponse)
    @app.get('/stored/cleanup',response_class=HTMLResponse)
    async def stored_form():return '<form method="post"><input name="message"></form>'
    @app.post('/stored/write')
    async def store(request:Request):
        from urllib.parse import parse_qs
        fields={k:v[0] for k,v in parse_qs((await request.body()).decode()).items()}
        app.state.stored[fields['record_id']]=fields;return {'stored':True}
    @app.get('/stored/read',response_class=HTMLResponse)
    async def stored_read(record_id:str='wva-probe',safe:bool=False):
        value=app.state.stored.get(record_id,{}).get('message','')
        return html.escape(value) if safe else value
    @app.post('/stored/cleanup')
    async def cleanup(request:Request):
        from urllib.parse import parse_qs
        fields={k:v[0] for k,v in parse_qs((await request.body()).decode()).items()}
        key=fields['record_id'];stored=app.state.stored.get(key)
        if stored and fields.get('wva_marker')!=stored.get('wva_marker'):return JSONResponse({},status_code=409)
        app.state.stored.pop(key,None);return {'cleaned':True}
    return app


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--port',type=int,default=18913)
    args=parser.parse_args();uvicorn.run(create_app(),host='127.0.0.1',port=args.port,log_level='error')
