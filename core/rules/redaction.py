import re

SENSITIVE=re.compile(r'^(authorization|cookie|set-cookie|password|passwd|api[_-]?key|access[_-]?token|refresh[_-]?token|csrf[_-]?token|user_token|secret)$',re.I)


def public_data(value,secrets=()):
    if isinstance(value,dict):
        secret_artifact=value.get('artifact_type',value.get('type','')) in ('api_key','auth_token','secret_key')
        return {key:'[REDACTED]' if SENSITIVE.match(key) or key=='value' and secret_artifact else public_data(item,secrets) for key,item in value.items()}
    if isinstance(value,(list,tuple)):return [public_data(item,secrets) for item in value]
    if isinstance(value,str):
        for secret in sorted((s for s in secrets if s and len(s)>=4),key=len,reverse=True):value=value.replace(secret,'[REDACTED]')
        return re.sub(r'([?&](?:api[_-]?key|token|access_token|user_token|password)=)[^&\s]+',r'\1[REDACTED]',value,flags=re.I)
    return value
