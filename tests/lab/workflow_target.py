"""Owned SQLite, header and configuration exposure fixture; loopback only."""
import argparse
import json
import sqlite3
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse
import uvicorn


def create_app():
    app=FastAPI(docs_url=None,openapi_url=None)
    app.state.fixed=False;app.state.code=200;app.state.csp=False;app.state.hits=[]
    @app.middleware('http')
    async def observe(request,call_next):
        app.state.hits.append((request.method,request.url.path,str(request.url.query)))
        response=await call_next(request)
        response.headers['Strict-Transport-Security']='max-age=3600'
        if app.state.csp:response.headers['Content-Security-Policy']="default-src 'self'"
        return response
    @app.get('/',response_class=HTMLResponse)
    async def root(request:Request):
        if app.state.code!=200:return HTMLResponse('blocked',status_code=app.state.code)
        value=request.query_params.get('id','1')
        with sqlite3.connect(':memory:') as db:
            db.executescript("CREATE TABLE items(id INTEGER,name TEXT); INSERT INTO items VALUES(1,'owned-item');")
            try:
                rows=db.execute('SELECT name FROM items WHERE id=?',(value,)).fetchall() if app.state.fixed else db.execute('SELECT name FROM items WHERE id='+value).fetchall()
            except sqlite3.Error:return HTMLResponse('SQLITE_ERROR',status_code=500)
        return '<h1>Owned inventory</h1><pre>'+json.dumps(rows)+'</pre>'
    @app.get('/.env',response_class=PlainTextResponse)
    async def env():
        return PlainTextResponse('missing',404) if app.state.fixed else 'APP_ENV=development\nDB_PASSWORD=owned-private-password-7283\n'
    @app.get('/.git/HEAD',response_class=PlainTextResponse)
    async def head():return PlainTextResponse('missing',404) if app.state.fixed else 'ref: refs/heads/main\n'
    @app.get('/.git/config',response_class=PlainTextResponse)
    async def config():return PlainTextResponse('missing',404) if app.state.fixed else '[core]\nrepositoryformatversion = 0\n'
    @app.get('/actuator/env')
    async def management():return JSONResponse({},404) if app.state.fixed else {'propertySources':[{'properties':{'service.api_key':{'value':'owned-private-api-key-9301'}}}]}
    @app.post('/__fixed')
    async def fixed():app.state.fixed=True;return {'fixed':True}
    from tests.lab.baseline_target import app as baseline
    for route in baseline.routes:
        if getattr(route,'path','') in ('/debug/version','/api/v1/user/profile','/api/v1/user/export','/api/v1/admin/config'):
            app.router.routes.append(route)
    return app


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--port',type=int,default=18915);args=parser.parse_args()
    uvicorn.run(create_app(),host='127.0.0.1',port=args.port,log_level='error')
