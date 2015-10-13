from __future__ import unicode_literals
import httplib2
import uuid

from flask import Flask, request, session, g, redirect, url_for, render_template
from oauth2client import client
from apiclient.discovery import build


DEBUG = True
SECRET_KEY = str(uuid.uuid4())
app = Flask(__name__)
app.config.from_object(__name__)


@app.before_request
def before_request():
    if 'oauth2_auth' in session:
        creds = client.OAuth2Credentials.from_json(session['oauth2_auth'])
        if creds.access_token_expired:
            return redirect(url_for('oauth2callback'))
        else:
            http_auth = creds.authorize(httplib2.Http())
            g.drive_service = build(
                'drive',
                'v2',
                http_auth,
                )


@app.route('/')
def index():
    files = None
    num_not_counted = None
    if 'oauth2_auth' in session:
        all_files = g.drive_service.files().list().execute()['items']
        files = [item for item in all_files if item.get('exportLinks', None)]
        num_not_counted = len(all_files) - len(files)

    return render_template(
        'index.html',
        files=files,
        num_not_counted=num_not_counted,
        )


@app.route('/oauth2callback')
def oauth2callback():
    code = request.args.get('code', None)
    flow = client.flow_from_clientsecrets(
        'client_secrets.json',
        scope='https://www.googleapis.com/auth/drive.metadata',
        redirect_uri=url_for('oauth2callback', _external=True),
        )

    if not code:
        return redirect(flow.step1_get_authorize_url())
    else:
        creds = flow.step2_exchange(code)
        session['oauth2_auth'] = creds.to_json()
        return redirect(url_for('index'))


@app.route('/revoke')
def revoke():
    if 'oauth2_auth' in session:
        creds = client.OAuth2Credentials.from_json(session['oauth2_auth'])
        try:
            creds.revoke(httplib2.Http())
        except client.TokenRevokeError:
            pass

        session.pop('oauth2_auth')

    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
