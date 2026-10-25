"""Small regression tests for core authentication and application flow."""
import io
import os
import tempfile
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

os.environ.setdefault("APP_ENV", "development")
os.environ.setdefault("SMS_PROVIDER", "console")
os.environ.setdefault("LOANDESK_DATA_DIR", tempfile.mkdtemp(prefix="loandesk-test-secrets-"))

from fastapi.testclient import TestClient
from PIL import Image
import backend.main as main


def make_client(tmp_path, monkeypatch):
    main.DB_PATH = Path(tmp_path) / "test.sqlite3"
    main.init_db()
    sent = []
    monkeypatch.setattr(main, "send_otp", lambda phone, code: sent.append((phone, code)))
    client = TestClient(main.app)
    return client, sent


def verify_user(client, sent, phone="+923001234567"):
    requested = client.post("/api/v1/auth/request-otp", json={"phone": phone})
    assert requested.status_code == 200
    data = requested.json()
    assert "otp" not in data
    challenge_id = data["challenge_id"]
    code = sent[-1][1]
    response = client.post("/api/v1/auth/verify-otp", json={"challenge_id": challenge_id, "otp": code})
    assert response.status_code == 200
    return response.json()["access_token"]


def test_otp_is_single_use_and_audit_does_not_store_codes(tmp_path, monkeypatch):
    client, sent = make_client(tmp_path, monkeypatch)
    r = client.post("/api/v1/auth/request-otp", json={"phone": "+923001234567"})
    assert r.status_code == 200
    challenge_id = r.json()["challenge_id"]
    code = sent[-1][1]
    wrong = "000000" if code != "000000" else "000001"
    bad = client.post("/api/v1/auth/verify-otp", json={"challenge_id": challenge_id, "otp": wrong})
    assert bad.status_code == 400
    with main.db_connect() as conn:
        audit = conn.execute("SELECT event,outcome FROM auth_audit ORDER BY created_at").fetchall()
        challenge = conn.execute("SELECT otp_hash,attempts FROM otp_challenges WHERE id=?", (challenge_id,)).fetchone()
    assert any(row["outcome"] == "incorrect" for row in audit)
    assert challenge["attempts"] == 1
    assert wrong not in str([tuple(row) for row in audit])
    ok = client.post("/api/v1/auth/verify-otp", json={"challenge_id": challenge_id, "otp": code})
    assert ok.status_code == 200
    reused = client.post("/api/v1/auth/verify-otp", json={"challenge_id": challenge_id, "otp": code})
    assert reused.status_code == 400


def test_kyc_account_and_admin_review_flow(tmp_path, monkeypatch):
    client, sent = make_client(tmp_path, monkeypatch)
    user_token = verify_user(client, sent, "+919876543210")
    headers = {"Authorization": f"Bearer {user_token}"}
    image_data = io.BytesIO()
    Image.new("RGB", (100, 100), (32, 130, 160)).save(image_data, format="JPEG")
    photo = image_data.getvalue()
    kyc = client.post(
        "/api/v1/application/kyc",
        headers=headers,
        data={"pan_number": "ABCDE1234F", "consent": "true"},
        files={"selfie": ("selfie.jpg", photo, "image/jpeg"), "pan_image": ("pan.jpg", photo, "image/jpeg")},
    )
    assert kyc.status_code == 200
    app_id = kyc.json()["application_id"]
    saved = client.post(
        "/api/v1/application/account",
        headers=headers,
        json={"account_holder": "Test Customer", "bank_name": "Test Bank", "account_number": "12345678900", "routing_code": "TEST0001"},
    )
    assert saved.status_code == 200
    admin_login = client.post("/api/v1/admin/login", json={"username": main.ADMIN_USERNAME, "password": main.ADMIN_PASSWORD})
    assert admin_login.status_code == 200
    admin_headers = {"Authorization": f"Bearer {admin_login.json()['access_token']}"}
    detail = client.get(f"/api/v1/admin/applications/{app_id}", headers=admin_headers)
    assert detail.status_code == 200
    assert detail.json()["account_saved"] is True
    reveal = client.post(f"/api/v1/admin/applications/{app_id}/reveal", headers=admin_headers, json={"purpose": "Review test application"})
    assert reveal.status_code == 200
    assert reveal.json()["account"]["account_number"] == "12345678900"
    update = client.patch(f"/api/v1/admin/applications/{app_id}", headers=admin_headers, json={"status": "approved", "review_note": "Reviewed", "offer_amount": 45000})
    assert update.status_code == 200
    user_app = client.get("/api/v1/application/me", headers=headers)
    assert user_app.json()["application"]["status"] == "approved"
