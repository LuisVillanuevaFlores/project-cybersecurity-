from crypt import methods
import os
from flask import Flask, flash, render_template, session, redirect
from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed
from flask_bootstrap import Bootstrap
from wtforms.fields import URLField, SubmitField, FileField
from werkzeug.utils import secure_filename
import re

from flask_wtf import FlaskForm
from wtforms import SubmitField
from flask_wtf.file import FileField, FileAllowed


app = Flask(__name__,
 template_folder='./templates',
 static_folder='./static')

bootstrap = Bootstrap(app)

class URLForm(FlaskForm):
    url = URLField('url')
    file = FileField()
    verify = SubmitField('Cargar')


def verified_https(url):
    url_pattern = "^https:\\/\\/(?:www\\.)?[-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{1,6}\\b(?:[-a-zA-Z0-9()@:%_\\+.~#?&\\/=]*)$"
    return re.match(url_pattern, url)

def validate_file(file):
    urls = []
    if file.content_type == 'text/plain':
        file.save(os.path.join(os.path.abspath(os.path.dirname(__file__)),secure_filename(file.filename)))
        with open(file.filename,'r') as file:
            for line in file:
                if not verified_https(line):
                    flash(f'La url {line} no satisface los requisitos, revisa que tenga el formato https')
                else:
                    urls.append(line)
            return urls
    else:
        flash(f'El archivo {file.filename} no es un archivo de texto plano .txt')


@app.route('/', methods=['GET', 'POST'])
def index():
    login_form = URLForm()
    urls = session.get('urls')
    url = session.get('url')
    context = {
        'login_form': login_form,
        'urls':urls,
        'url': url
    }
    if login_form.validate_on_submit():
        url = login_form.url.data
        file = login_form.file.data
        session.clear()
        if url:
            if not verified_https(url):
                flash("La URL no satisface los requisitos, revisa que tenga el formato https")
        if file:
            urls = validate_file(file)
        session['urls']=urls
        session['url'] = url
        return redirect('/')
    return render_template('index.html', **context)

if __name__=='__main__':
    app.config['WTF_CSRF_ENABLED']= False
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['ENV']='development'
    app.config['SECRET_KEY']='KEY_SECRET'
    app.run(debug=True)