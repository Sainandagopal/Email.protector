# pyrefly: ignore [missing-import]
from fastapi.testclient import TestClient
from app.main import app

def test_full_pipeline_integration():
    client = TestClient(app)

    # 1. Health
    h_res = client.get('/api/v1/health')
    assert h_res.status_code == 200
    assert h_res.json()['status'] == 'online'

    import os
    sample_path = 'samples/phishing_paypal_urgent.eml'
    if not os.path.exists(sample_path):
        sample_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'samples', 'phishing_paypal_urgent.eml'))

    with open(sample_path, 'r', encoding='utf-8', errors='ignore') as f:
        eml_content = f.read()

    payload = {'raw_eml': eml_content}
    a_res = client.post('/api/v1/analyze/email', json=payload)
    assert a_res.status_code == 200

    data = a_res.json()
    assert data['threat_score'] >= 50
    assert data['classification'] in ('PHISHING', 'MALICIOUS')
    assert len(data['iocs']) > 0
    assert len(data['urls']) > 0
    assert data['geo'] is not None
    assert data['geo']['country'] in ('Russia', 'Germany', 'DE', 'RU')

    inv_id = data['id']

    # 3. Fetch Detail
    det_res = client.get(f'/api/v1/investigations/{inv_id}')
    assert det_res.status_code == 200
    assert det_res.json()['subject'] == data['subject']

    # 4. Graph endpoint
    gr_res = client.get(f'/api/v1/investigations/{inv_id}/graph')
    assert gr_res.status_code == 200
    assert len(gr_res.json()['nodes']) > 0

    # 5. Report HTML
    rep_res = client.get(f'/api/v1/reports/{inv_id}/html')
    assert rep_res.status_code == 200
    assert 'SIH-Guard Cyber Forensics Dossier' in rep_res.text
