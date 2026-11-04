"""Owned real-I/O positive/defended fixture. Binds only through LocalTestbed.

Only a tightly validated echo/printf command can run. No arbitrary shell input.
Files are confined to the supplied pytest temporary directory.
"""
import asyncio
from email.parser import BytesParser
from email.policy import default
import os
from pathlib import Path
import re
import subprocess
from urllib.parse import parse_qs
import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse


def create_app(directory):
    root=Path(directory); public=root/'public';public.mkdir(parents=True,exist_ok=True)
    marker='WVA_BENIGN_FILE_CANARY_6e6de08c'
    (public/'guide.txt').write_text('guide',encoding='utf-8')
    (root/'canary.txt').write_text(marker,encoding='utf-8')
    app=FastAPI(docs_url=None,openapi_url=None)
    app.state.receipts={};app.state.files={};app.state.hits=[]
    @app.get('/',response_class=PlainTextResponse)
    async def index():return 'WVA owned evidence fixture'
    @app.middleware('http')
    async def log(request,call_next):
        app.state.hits.append((request.method,request.url.path))
        return await call_next(request)

    @app.get('/file/{mode}',response_class=PlainTextResponse)
    async def file(mode:str,value:str='guide.txt'):
        path=(public/value).resolve()
        if not path.is_relative_to(root.resolve()):return PlainTextResponse('outside fixture',403)
        if mode=='safe' and not path.is_relative_to(public.resolve()):return 'denied'
        return path.read_text(encoding='utf-8') if path.is_file() else 'not found'

    @app.get('/command/{mode}',response_class=PlainTextResponse)
    async def command(mode:str,value:str='control'):
        if mode in ('safe','reflection'):return value
        if os.name=='nt':
            if not re.fullmatch(r'127\.0\.0\.1&echo wva_[a-f0-9]+\^[a-f0-9]+',value):return 'control'
            command=value.split('&',1)[1]
            args=['cmd.exe','/d','/s','/c',command]
        else:
            if not re.fullmatch(r"127\.0\.0\.1;printf '%s%s\\n' 'wva_[a-f0-9]+' '[a-f0-9]+'",value):return 'control'
            args=['/bin/sh','-c',value.split(';',1)[1]]
        result=await asyncio.to_thread(subprocess.run,args,capture_output=True,text=True,timeout=2)
        return result.stdout

    @app.get('/callback/{marker}')
    async def callback(marker:str):
        app.state.receipts[marker]=app.state.receipts.get(marker,0)+1
        return {'received':True}
    @app.get('/receipt/{marker}')
    async def receipt(marker:str):return {'marker':marker,'count':app.state.receipts.get(marker,0)}
    @app.get('/ssrf/{mode}',response_class=PlainTextResponse)
    async def ssrf(request:Request,mode:str,value:str='control'):
        if mode=='safe':return 'blocked'
        if mode=='reflection':return value+' Cloud Metadata Service'
        prefix=str(request.base_url)+'callback/'
        if not value.startswith(prefix) or not re.fullmatch('[a-f0-9]{32}',value[len(prefix):]):return 'control'
        async with httpx.AsyncClient(trust_env=False) as client:
            response=await client.get(value)
        return response.text

    @app.get('/files/{filename}',response_class=PlainTextResponse)
    async def read(filename:str):
        value=app.state.files.get(filename)
        return PlainTextResponse(value,200) if value is not None else PlainTextResponse('missing',404)
    @app.post('/upload/{mode}')
    async def upload(request:Request,mode:str):
        body=await request.body()
        parsed=BytesParser(policy=default).parsebytes(('Content-Type: '+request.headers['content-type']+'\r\nMIME-Version: 1.0\r\n\r\n').encode()+body)
        parts=list(parsed.iter_parts());part=next(p for p in parts if p.get_filename())
        filename=part.get_filename()
        if not re.fullmatch(r'wva_[a-f0-9]{32}\.php',filename):return JSONResponse({},400)
        if mode=='reject':return {'error':'Rejected file '+filename}
        if mode=='safe':return JSONResponse({'error':'extension denied'},415)
        # The bytes are plain random text. Never interpret or execute the uploaded file.
        app.state.files[filename]=part.get_payload(decode=True).decode()
        return {'success':True}
    @app.post('/cleanup/{mode}')
    async def cleanup(request:Request,mode:str):
        fields={k:v[0] for k,v in parse_qs((await request.body()).decode()).items()}
        if mode=='fail':return JSONResponse({'error':'fixture cleanup failure'},500)
        name=fields.get('filename','')
        if app.state.files.get(name) not in (None,fields.get('wva_marker')):return JSONResponse({},409)
        app.state.files.pop(name,None)
        return {'cleaned':True}
    return app
