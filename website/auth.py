import json
import os

import requests
from flask import Blueprint, render_template, request, flash, redirect, url_for
from oauthlib.oauth2 import WebApplicationClient

from .models import User
from werkzeug.security import check_password_hash, generate_password_hash
from flask_login import login_required, login_user, logout_user, current_user
from website import db

auth = Blueprint('auth', __name__)
GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration"
)
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', None)
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', None)
client = WebApplicationClient(GOOGLE_CLIENT_ID)


@auth.route('/google', methods=['GET'])
def google():
    google_provider_config = get_google_provider_config()
    authorization_endpoint = google_provider_config['authorization_endpoint']
    return redirect(client.prepare_request_uri(authorization_endpoint,
                                               request.host_url + "callback",
                                               ['openid', 'email', 'profile'])
                    )


@auth.route('/callback')
def callback():
    code = request.args.get('code')
    google_provider_config = get_google_provider_config()
    token_endpoint = google_provider_config['token_endpoint']
    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET)
    )
    client.parse_request_body_response(json.dumps(token_response.json()))
    userinfo_endpoint = google_provider_config['userinfo_endpoint']
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body).json()
    if userinfo_response.get('email_verified'):
        # unique_id = userinfo_response['sub']
        users_email = userinfo_response['email']
        # picture = userinfo_response['picture']
        first_name = userinfo_response['given_name']
        last_name = userinfo_response['family_name']
        user = User.query.filter_by(email=users_email).first()
        if not user:
            user = User(email=users_email, password='', first_name=first_name,
                        last_name=last_name, phone='', type='GOOGLE')
            db.session.add(user)
            db.session.commit()
        if user.type != "GOOGLE":
            flash('Looks like you have signed in using username and password before, try logging in using username '
                  'and password combination', category='error')
        else:
            flash('Signed in successfully', category='success')
            login_user(user, remember=True)
    else:
        flash('Unable to login', category='error')
    if current_user.is_authenticated:
        # return redirect(url_for('views.home'))
        return render_template("home.html", user=current_user)
    else:
        return render_template("login.html", user=current_user)


def get_google_provider_config():
    return requests.get(GOOGLE_DISCOVERY_URL).json()


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        user = User.query.filter_by(email=email).first()
        if user:
            if user.type == "GOOGLE":
                flash('It appears you have used Google to sign in before. Please try using Google sign in.',
                      category='error')
            elif check_password_hash(user.password, password):
                flash('Logged in successfully', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Invalid password', category='error')
        else:
            flash('User does not exist', category='error')
    if current_user.is_authenticated:
        # return redirect(url_for('views.home'))
        return render_template("home.html", user=current_user)
    else:
        return render_template("login.html", user=current_user)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))


@auth.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == "POST":
        email = request.form.get("email")
        firstName = request.form.get("firstName")
        lastName = request.form.get("lastName")
        password = request.form.get("password")
        confirm = request.form.get("confirm")
        phone = request.form.get("phone")
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already registered, or could have used Google sign in before.', category='success')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters', category='error')
        elif password != confirm:
            flash('Passwords dont match', category='error')
        else:
            user = User(email=email, password=generate_password_hash(password), first_name=firstName,
                        last_name=lastName, phone=phone, type='CUSTOM')
            db.session.add(user)
            db.session.commit()
            flash('Account created', category='success')
            login_user(user, remember=True)
            # return redirect(url_for('views.home'))
            return render_template("home.html", user=current_user)
    return render_template("sign_up.html", user=current_user)
