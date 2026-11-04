import hashlib
import importlib.util
from pathlib import Path
import pytest


@pytest.mark.parametrize('tamper',['none','source','binary'])
def test_build_verification_binds_source_and_binary(tmp_path,monkeypatch,tamper):
    path=Path(__file__).resolve().parents[1]/'packaging/build_manifest.py'
    spec=importlib.util.spec_from_file_location('wva_build_manifest',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    monkeypatch.setattr(module,'ROOT',tmp_path)
    monkeypatch.setattr(module,'sources',lambda:{'module.py':'source-current'})
    (tmp_path/'WVA.exe').write_bytes(b'owned-test-binary')
    data={'bytes':17,'sha256':hashlib.sha256(b'owned-test-binary').hexdigest(),'source_files':{'module.py':'source-current'}}
    if tamper=='source':data['source_files']['module.py']='source-old'
    if tamper=='binary':(tmp_path/'WVA.exe').write_bytes(b'other-test-binary')
    assert module.verify(data)==(tamper=='none')
