import pytest
from app import app as flask_app


@pytest.fixture()
def client():
    flask_app.config["TESTING"] = True
    with flask_app.test_client() as c:
        yield c


def test_home_returns_200(client):
    resp = client.get("/")
    assert resp.status_code == 200


def test_login_page(client):
    resp = client.get("/login")
    assert resp.status_code == 200
