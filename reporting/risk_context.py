"""Explain a finding without treating a possible attack as an observed exploit."""
from copy import deepcopy

OWASP = "https://cheatsheetseries.owasp.org/cheatsheets/"
PROFILES = {
    "CSP": {
        "summary": "페이지가 불러올 스크립트와 외부 리소스를 제한하는 브라우저 정책이 없습니다.",
        "observation": "검사한 응답에서 강제 Content-Security-Policy 헤더를 확인하지 못했습니다.",
        "assessment": "보안 정책 누락 확인",
        "attacks": [{"name": "스크립트 삽입 공격의 피해 확대", "scenario": "다른 기능에 스크립트 삽입 취약점이 있다면, 악성 스크립트가 사용자 화면을 바꾸거나 사용자 권한으로 요청을 보낼 수 있습니다.", "conditions": ["별도의 XSS 또는 스크립트 삽입 경로가 있어야 합니다.", "악성 코드가 실행 가능한 위치에 들어가고 다른 방어 정책도 이를 막지 못해야 합니다."]}],
        "limits": ["CSP 누락만으로 XSS가 존재하거나 스크립트 실행에 성공했다고 판정하지 않습니다.", "현재 검사는 브라우저에서 악성 스크립트 실행을 재현하지 않았습니다."],
        "references": [{"title": "OWASP CSP 안내", "url": OWASP + "Content_Security_Policy_Cheat_Sheet.html"}]},
    "HSTS": {
        "summary": "브라우저에 이 사이트를 HTTPS로만 연결하도록 기억시키는 정책이 없습니다.",
        "observation": "HTTPS 응답에서 Strict-Transport-Security 헤더를 확인하지 못했습니다.",
        "assessment": "HTTPS 강제 정책 누락 확인",
        "attacks": [{"name": "초기 HTTP 연결의 도청과 변조", "scenario": "사용자가 HTTP로 접속하는 상황에서 네트워크 공격자가 연결을 가로채면, 평문으로 전송되는 정보가 노출되거나 응답이 바뀔 수 있습니다.", "conditions": ["공격자가 사용자의 네트워크 경로에 개입할 수 있어야 합니다.", "HTTP 접속이 발생하고 기존 HSTS 기록·사전 등록·HTTPS 우선 연결 등 다른 보호가 적용되지 않아야 합니다."]}],
        "limits": ["헤더 누락은 정상 HTTPS 암호화가 깨졌다는 뜻이 아닙니다.", "실제 네트워크 가로채기와 브라우저의 기존 정책 저장 상태는 확인하지 않았습니다."],
        "references": [{"title": "OWASP HSTS 안내", "url": OWASP + "HTTP_Strict_Transport_Security_Cheat_Sheet.html"}]},
    "EXPOSED_DEBUG_ENDPOINT": {
        "summary": "인증 없이 내부 식별자나 환경 정보를 읽을 수 있는 디버그 응답이 있습니다.",
        "observation": "미인증 요청의 디버그 응답에서 사용자 식별자 또는 키·토큰에 해당하는 필드를 관찰했습니다.",
        "assessment": "정보 노출 응답 확인",
        "attacks": [{"name": "노출 정보를 이용한 후속 접근", "scenario": "노출된 사용자 식별자는 보호되지 않은 객체 조회에, 유효한 키나 토큰은 해당 자격증명이 허용하는 기능 접근에 이용될 수 있습니다.", "conditions": ["식별자를 이용할 수 있는 접근 통제 취약점 또는 유효한 인증정보가 추가로 존재해야 합니다.", "노출 정보와 후속 요청이 같은 계정·객체·권한 범위에 연결되어야 합니다."]}],
        "limits": ["식별자 노출만으로 계정 탈취나 관리자 접근 성공을 뜻하지 않습니다.", "후속 단계는 별도의 발견 항목과 연계 경로 증거를 함께 확인해야 합니다."],
        "references": [{"title": "OWASP 오류 및 정보 노출 안내", "url": OWASP + "Error_Handling_Cheat_Sheet.html"}]},
    "BOLA_IDOR": {
        "summary": "요청한 사용자 식별자에 대해 인증 없이 프로필의 역할 또는 인증정보가 반환되었습니다.",
        "observation": "세션 인증을 보내지 않은 요청에서 일치하는 사용자 식별자와 역할 또는 키 필드를 관찰했습니다.",
        "assessment": "미인증 객체 응답 확인",
        "attacks": [{"name": "다른 사용자의 정보 열람", "scenario": "객체 소유권 검사가 없다면, 권한이 없는 사용자가 식별자를 바꾸어 타인의 비공개 프로필이나 업무 정보를 읽을 수 있습니다.", "conditions": ["해당 객체가 원래 비공개이며 요청자에게 조회 권한이 없어야 합니다.", "유효한 객체 식별자를 알고 있거나 허가된 범위에서 얻을 수 있어야 합니다."]}, {"name": "응답에 노출된 키의 재사용", "scenario": "프로필에 유효한 키가 들어 있다면, 공격자는 그 키에 부여된 권한으로 다른 기능에 접근할 수 있습니다.", "conditions": ["응답에 실제로 사용 가능한 키가 포함되어야 합니다.", "다른 기능이 그 키를 받아들이고 필요한 권한도 부여되어 있어야 합니다."]}],
        "limits": ["현재 검사는 두 실제 계정의 소유권과 공개·비공개 정책을 대조하지 않았습니다.", "정보 수정·삭제나 키를 이용한 추가 피해는 별도로 확인해야 합니다."],
        "references": [{"title": "OWASP API 객체 접근 통제 안내", "url": "https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/"}]},
    "PRIVILEGE_ESCALATION": {
        "summary": "앞 단계에서 수집한 키로 관리자 상태가 포함된 응답을 읽었습니다.",
        "observation": "수집 키를 전달한 관리자 경로가 HTTP 200과 ADMIN 권한 필드를 반환했습니다.",
        "assessment": "관리자 응답 조회 확인",
        "attacks": [{"name": "관리자 정보의 무단 열람", "scenario": "관리자 응답에 내부 설정이나 민감 정보가 있다면, 키를 확보한 사람이 해당 정보를 읽을 수 있습니다.", "conditions": ["노출된 키가 유효하고 관리자 조회 경로에서 받아들여져야 합니다.", "응답이 실제 관리 기능에 해당하는지와 정보의 민감도를 확인해야 합니다."]}, {"name": "권한 있는 기능으로의 추가 접근", "scenario": "같은 키가 다른 관리 기능에도 사용되고 역할 검사가 부족하다면, 키 권한 범위의 추가 기능이 노출될 수 있습니다.", "conditions": ["별도의 관리 기능이 같은 키를 허용해야 합니다.", "실제 작업 권한과 기능별 인가 검증을 추가 확인해야 합니다."]}],
        "limits": ["확인된 동작은 관리자 응답 조회입니다. 설정 변경·데이터 삭제·임의 코드 실행은 수행하지 않았습니다.", "이 결과를 서버 전체 장악이나 모든 관리자 기능 사용 가능으로 확대하지 않습니다."],
        "references": [{"title": "OWASP 인가 검증 안내", "url": OWASP + "Authorization_Cheat_Sheet.html"}]},
    "CORS_MISCONFIGURATION": {
        "summary": "허용하지 않아야 할 출처에 인증 응답 읽기를 허용하는 CORS 헤더가 관찰됐습니다.",
        "observation": "테스트 Origin이 응답에 반사되었고 Access-Control-Allow-Credentials 값이 true였습니다.",
        "assessment": "교차 출처 허용 헤더 확인",
        "attacks": [{"name": "공격자 사이트에서 사용자 응답 읽기", "scenario": "사용자가 공격자 사이트를 방문하면, 그 사이트가 사용자 인증정보를 포함한 요청을 보내고 민감한 응답을 읽을 수 있습니다.", "conditions": ["브라우저가 해당 요청에 쿠키 등 유효한 인증정보를 실제로 전송해야 합니다.", "SameSite·제3자 쿠키 제한·사전 요청 등 브라우저 조건을 통과하고 응답에 보호할 정보가 있어야 합니다."]}],
        "limits": ["헤더 조합을 관찰했으며 실제 사용자 세션을 사용한 브라우저 유출은 재현하지 않았습니다.", "공개 응답에 대한 출처 허용만으로 민감정보 유출을 단정하지 않습니다."],
        "references": [{"title": "OWASP CORS 안내", "url": OWASP + "HTML5_Security_Cheat_Sheet.html#cross-origin-resource-sharing"}]},
    "COOKIE_SECURITY_FLAG": {
        "summary": "응답 쿠키에 Secure 또는 HttpOnly 보호 속성이 빠진 항목이 있습니다.",
        "observation": "검사한 응답의 쿠키 속성에서 누락된 보호 설정이 보고되었습니다.",
        "assessment": "쿠키 보호 속성 누락 확인",
        "attacks": [{"name": "세션 쿠키 노출과 도용", "scenario": "Secure가 없는 인증 쿠키는 HTTP 전송 시 노출될 수 있고, HttpOnly가 없는 쿠키는 별도의 XSS가 있으면 스크립트로 읽힐 수 있습니다. 유효한 세션 쿠키라면 계정 도용으로 이어질 수 있습니다.", "conditions": ["문제 쿠키가 인증이나 민감한 상태를 유지하는 값이어야 합니다.", "누락된 속성에 따라 HTTP 전송 또는 별도의 스크립트 실행 취약점이 성립해야 합니다.", "세션 만료·기기 결합 등 추가 보호도 고려해야 합니다."]}],
        "limits": ["쿠키 이름만으로 인증 쿠키임을 확정하지 않으며 실제 도용은 수행하지 않았습니다.", "HttpOnly는 쿠키의 스크립트 읽기를 제한하며 모든 CSRF나 XSS 피해를 막는 속성은 아닙니다."],
        "references": [{"title": "OWASP 세션 쿠키 안내", "url": OWASP + "Session_Management_Cheat_Sheet.html"}]},
}


PROFILES.update({
    'POLICY_OBJECT':{'summary':'비공개로 지정한 객체가 허용되지 않은 계정에도 노출됐습니다.','observation':'소유자의 정상 응답과 거부 대상 계정의 보호 필드 값을 대조했습니다.','assessment':'명시한 계정·객체 정책 위반 확인',
        'attacks':[{'name':'다른 계정의 비공개 정보 조회','scenario':'객체 식별자를 아는 사용자가 허용되지 않은 보호 데이터를 조회할 수 있습니다.','conditions':['정책상 비공개인 객체와 접근 가능한 식별자가 있어야 합니다.','조회 응답에 보호 정보가 실제로 포함돼야 합니다.']}],
        'limits':['제공한 테스트 계정·객체·보호 필드의 정책을 기준으로 합니다. 공개·공유 객체를 자동으로 비공개라고 추정하지 않습니다.','변경·삭제 권한은 검사하지 않았습니다.'],'references':[{'title':'OWASP Authorization','url':OWASP+'Authorization_Cheat_Sheet.html'}]},
    'POLICY_ROLE':{'summary':'관리자 전용으로 지정한 응답이 비관리자에게도 노출됐습니다.','observation':'관리자의 안정적인 보호 응답과 거부 대상으로 지정한 계정의 동일 필드를 대조했습니다.','assessment':'명시한 역할 정책 위반 확인',
        'attacks':[{'name':'관리자 전용 정보의 무단 조회','scenario':'일반 계정 또는 미인증 요청자가 정책상 관리자에게만 허용한 정보를 읽을 수 있습니다.','conditions':['서버 기능이 실제 보호 데이터를 반환해야 합니다.','해당 계정은 명시한 정책상 허용되지 않아야 합니다.']}],
        'limits':['보호 응답 읽기만 검사했습니다. 모든 관리자 작업 권한이나 시스템 장악을 증명하지 않습니다.'],'references':[{'title':'OWASP Authorization','url':OWASP+'Authorization_Cheat_Sheet.html'}]},
    "SCRIPT_SECRET": {
        "summary": "브라우저에 배포된 JavaScript에서 자격증명 형식의 문자열이 발견됐습니다.",
        "observation": "최대 5개 스크립트의 제한된 본문에서 키·토큰·개인 키 헤더 패턴을 확인했습니다.",
        "assessment": "자격증명 패턴 노출 확인",
        "attacks": [{"name": "노출된 인증정보의 무단 사용", "scenario": "값이 실제 비밀 자격증명이고 아직 유효하다면, 그 권한으로 API를 호출하거나 정보에 접근하고 비용을 발생시킬 수 있습니다.", "conditions": ["공개용 API 식별자나 예제 값이 아닌 실제 비밀 값이어야 합니다.", "값이 유효하고 사용 가능한 권한·접근 경로가 있어야 합니다."]}],
        "limits": ["패턴을 탐지했으며 키의 유효성이나 실제 사용 권한을 검증하지 않았습니다.", "공개용 키·테스트 값은 오탐일 수 있습니다. 원문 값은 마스킹된 증거와 분리하여 소유자가 확인해야 합니다."],
        "references": []},
    "TLS_EXPIRING": {
        "summary": "검사한 TLS 인증서의 유효기간이 15일 이내로 남아 있습니다.",
        "observation": "정상 인증서 검증이 가능한 TLS 연결에서 인증서 만료일을 확인했습니다.",
        "assessment": "인증서 만료일 확인",
        "attacks": [{"name": "인증서 경고 우회를 이용한 사칭 연결", "scenario": "인증서가 만료된 뒤 사용자가 경고를 무시하도록 유도된다면, 추가로 연결에 개입한 공격자의 사칭 연결을 받아들일 위험이 있습니다. 직접적인 운영 영향은 정상 TLS 연결 실패입니다.", "conditions": ["인증서가 만료되고 사용자나 클라이언트가 검증을 우회해야 합니다.", "공격자가 연결이나 접속 주소에 별도로 개입할 수 있어야 합니다."]}],
        "limits": ["만료 임박은 공격 성공을 뜻하지 않으며 인증서 검증을 유지하면 잘못된 연결을 거부합니다.", "이미 만료되거나 신뢰할 수 없는 인증서는 연결 오류가 될 수 있습니다. 전체 TLS 설정·암호군 검사는 수행하지 않습니다."],
        "references": []},
})

PROFILES.update({
    'SQL_INJECTION': {
        'summary':'입력값의 SQL 조건 변경이 데이터 조회 결과에 영향을 줬습니다.',
        'observation':'정상 기준과 참·거짓 조건을 반복 대조했습니다. 시간 기반 항목은 명시한 로컬 시나리오의 지연 차이로 확인했습니다.',
        'assessment':'반복 조건 대조 확인',
        'attacks':[{'name':'의도하지 않은 데이터 조회','scenario':'SQL 문법이 입력값으로 분리되지 않으면 조회 범위나 조건이 조작될 수 있습니다.','conditions':['입력값이 SQL 문맥에서 처리돼야 합니다.','공격자가 활용할 수 있는 DB 권한과 쿼리 형태가 있어야 합니다.']}],
        'limits':['이번 검사는 조건 차이만 확인했습니다. 다른 테이블·비밀번호 추출, DB 쓰기, OS 명령 실행은 하지 않았습니다.','검사한 매개변수·세션·조회 경로 밖의 모든 SQL 주입을 탐지한다는 뜻이 아닙니다.'],
        'references':[{'title':'OWASP SQL Injection Prevention','url':OWASP+'SQL_Injection_Prevention_Cheat_Sheet.html'}]},
    'XSS': {
        'summary':'사용자 입력에서 유래한 코드가 브라우저 문서에서 실행됐습니다.',
        'observation':'별도 브라우저 컨텍스트에서 고유 실행 표식과 문서 출처를 확인했습니다. 반사·DOM·저장형 구분은 관찰 증거를 따릅니다.',
        'assessment':'브라우저 실행 표식 확인',
        'attacks':[{'name':'사용자 화면과 브라우저 동작 조작','scenario':'피해자가 해당 입력을 포함한 페이지를 열면 스크립트가 페이지 내용을 바꾸거나 사용자 권한의 동작을 시도할 수 있습니다.','conditions':['피해자가 취약한 입력이 포함된 문서를 열어야 합니다.','실행 문맥과 CSP·브라우저 방어 정책이 해당 코드를 허용해야 합니다.']}],
        'limits':['고유 표식만 실행했으며 사용자 쿠키 읽기·외부 전송·계정 작업은 수행하지 않았습니다.','특정 브라우저·문서·입력에 대한 실행 확인이며 모든 XSS 문맥이나 피해 규모를 증명하지 않습니다.'],
        'references':[{'title':'OWASP XSS Prevention','url':OWASP+'Cross_Site_Scripting_Prevention_Cheat_Sheet.html'}]}
})



PROFILES.update({
    'CREDENTIAL_RESPONSE': {
        'summary':'별도 미인증 요청에서 사용자 식별자와 자격증명 필드가 반복 반환됐습니다.',
        'observation':'인증 헤더·쿠키가 없는 요청에서 같은 식별자와 키 필드가 두 번 일치했습니다.',
        'assessment':'미인증 자격증명 응답 확인',
        'attacks':[{'name':'노출 키를 이용한 접근','scenario':'키가 실제 유효하고 보호 기능에서 받아들여지면 해당 키가 허용하는 응답에 접근할 수 있습니다.','conditions':['노출 값이 실제 인증정보여야 합니다.','후속 기능이 같은 키를 허용해야 하며 별도 접근 증거가 필요합니다.']}],
        'limits':['필드 이름만으로 키의 유효성이나 객체 소유권 위반을 확정하지 않습니다.','키 사용 결과는 별도 발견 항목에서 확인합니다.'],
        'references':[]},
    'PATH_TRAVERSAL': {
        'summary': '파일 조회 경로 밖에 둔 무해한 실습 표식 파일이 반환됐습니다.',
        'observation': '정상 기준 응답과 달리 명시한 실습 경로에서 알려진 파일 표식이 두 번 일치했습니다.',
        'assessment': '실습 표식 파일 읽기 확인',
        'attacks': [{
            'name': '서버 설정 파일 및 자격증명 열람',
            'scenario': '공격자가 서버 파일 시스템의 환경변수, 소스코드, 데이터베이스 연결 정보, 비밀키를 직접 열람할 수 있습니다.',
            'conditions': ['웹 프로세스에 해당 파일 읽기 권한이 있어야 합니다.', '입력 경로 정규화 및 상위 디렉터리 이동 필터링이 누락되어야 합니다.']
        }],
        'limits': ['명시한 무해한 표식 파일만 읽었습니다. 운영체제 파일·자격증명 열람이나 쓰기·삭제는 입증하지 않습니다.'],
        'references': [{'title': 'OWASP Path Traversal', 'url': OWASP + 'Path_Traversal_Cheat_Sheet.html'}]
    },
    'COMMAND_INJECTION': {
        'summary': '사용자 입력이 서버 측 운영체제 명령어 실행 경로로 직접 전달되었습니다.',
        'observation': '입력 원문에 연속해서 포함되지 않은 고유 출력 표식이 서로 다른 두 번의 대조에서 반환됐습니다.',
        'assessment': '원격 시스템 명령 실행 확인',
        'attacks': [{
            'name': '서버 운영체제 권한 장악 (RCE)',
            'scenario': '원격 공격자가 웹 서버 권한으로 임의의 시스템 명령을 실행하여 서버를 완전 장악하거나 내부망으로 침투할 수 있습니다.',
            'conditions': ['시스템 쉘 호출 함수(system, exec 등)가 입력을 적절히 정화하지 않고 실행해야 합니다.', '웹 서버 프로세스의 시스템 권한에 따라 실행 범위가 결정됩니다.']
        }],
        'limits': ['로컬 실습의 무해한 표식 출력만 확인했습니다. 실행 계정 권한·SYSTEM 권한·서버 장악은 확인하지 않았습니다.'],
        'references': [{'title': 'OWASP Command Injection Prevention', 'url': OWASP + 'OS_Command_Injection_Defense_Cheat_Sheet.html'}]
    },
    'SSRF': {
        'summary': '서버 요청과 로컬 실습 수신기의 고유 요청 기록이 연결됐습니다.',
        'observation': '정상 대조에서는 수신 횟수 0, 각 고유 URL을 전달한 뒤에는 1회 수신이 두 번 확인됐습니다.',
        'assessment': '서버 측 요청 위조 확인',
        'attacks': [{
            'name': '내부 클라우드 자격증명 탈취 및 비공개 내부망 스캔',
            'scenario': '외부에서 접근할 수 없는 내부 인프라, 관리 포털, 클라우드 IAM 임시 자격증명(AccessKeyId)을 서버 권한으로 탈취할 수 있습니다.',
            'conditions': ['서버가 사용자가 지정한 임의 URL로 아웃바운드 연결을 시도해야 합니다.', '내부망 방화벽 또는 사설 IP 필터링이 부재해야 합니다.']
        }],
        'limits': ['명시한 로컬 수신기만 사용했습니다. 클라우드 메타데이터 접근·자격증명 탈취·내부망 전체 접근은 검증하지 않았습니다.'],
        'references': [{'title': 'OWASP Server-Side Request Forgery Prevention', 'url': OWASP + 'Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html'}]
    },
    'ARBITRARY_FILE_UPLOAD': {
        'summary': '위험 확장자의 무해한 텍스트 파일 저장과 별도 조회가 허용됐습니다.',
        'observation': '명시적인 저장 성공 뒤 고유 파일 내용이 두 번 조회됐고 정리 후 파일 부재를 확인했습니다.',
        'assessment': '위험 확장자 파일 업로드 확인',
        'attacks': [{
            'name': '웹쉘(WebShell) 업로드를 통한 원격 코드 실행',
            'scenario': '공격자가 웹쉘 스크립트를 업로드한 후 웹 브라우저로 해당 파일 경로에 접근하여 서버 제어권을 획득할 수 있습니다.',
            'conditions': ['업로드된 파일이 웹 루트(Web Root) 아래 저장되어 직접 실행/호출 가능해야 합니다.', '파일 확장자 검증 및 실행 권한 제어가 누락되어야 합니다.']
        }],
        'limits': ['고유 텍스트 파일의 저장·조회·정리만 확인했습니다. 서버 측 스크립트 실행이나 웹쉘 동작은 입증하지 않습니다.'],
        'references': [{'title': 'OWASP File Upload Cheat Sheet', 'url': OWASP + 'File_Upload_Cheat_Sheet.html'}]
    }
})

def risk_context(data, rule_key):
    profile = PROFILES.get(rule_key)
    if profile:
        return deepcopy(profile)
    return {"summary": "현재 증거를 바탕으로 문제의 영향 범위를 추가 확인해야 합니다.",
            "observation": "아래 관찰 증거와 원문 설명을 확인하세요.", "assessment": "추가 검토 필요",
            "attacks": [], "limits": ["이 유형에 검증된 공격 설명이 등록되지 않아 공격 가능성을 자동으로 단정하지 않습니다."], "references": []}


def risk_context_lines(context):
    lines = ["#### 진단 내용", "", context["summary"], "", "- 확인 내용: " + context["observation"], "- 확인 수준: " + context["assessment"], "", "#### 가능한 공격", ""]
    if not context["attacks"]:
        lines.append("증거를 추가 검토한 뒤 공격 성립 여부를 판단해야 합니다.")
    for attack in context["attacks"]:
        lines += ["**" + attack["name"] + "**", "", attack["scenario"], "", "성립 조건:"]
        lines += ["- " + item for item in attack["conditions"]]
        lines.append("")
    lines += ["#### 확인 범위", ""] + ["- " + item for item in context["limits"]] + [""]
    return lines
