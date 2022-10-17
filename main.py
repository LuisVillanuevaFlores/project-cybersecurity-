from distutils import errors
import os
import re

from asn1crypto import pem
from asn1crypto.x509 import Certificate
from certvalidator import CertificateValidator
from flask import Flask
from flask import flash
from flask import redirect
from flask import render_template
from flask import session
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from oscrypto import tls
from werkzeug.utils import secure_filename
from wtforms import SubmitField
from wtforms.fields import FileField
from wtforms.fields import SubmitField
from wtforms.fields import URLField

CERTIFICATES = {}

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


def get_relevant_certificate_data(url):
    if url in [None, '']:
        return None
    host = re.search(r'https://([^/?:]*)', url).group(1)
    try:
        connection = tls.TLSSocket(host, 443, session=tls.TLSSession(manual_validation=True))
    except Exception as e:
        return None
    certificate_data = dict(
        in_mozilla=False,
        in_chrome=False,
        in_edge=False,
        mozilla_trust_level=1,
        chrome_trust_level=1,
        edge_trust_level=1,
    )
    

    validator = CertificateValidator(connection.certificate, connection.intermediates)

    try:
        certification_chain = validator.validate_tls(connection.hostname)
    except Exception as e:
        flash(f'No se encontró un certificado válido para la url: {url}, revisarla')
        return certificate_data
    root_certificate = certification_chain[0]

    for mozilla_certificate in CERTIFICATES.get('mozilla_certificates'):
        if mozilla_certificate.key_identifier_value == root_certificate.key_identifier_value:
            certificate_data.update({
                'in_mozilla': True
            })
    for chrome_certificate in CERTIFICATES.get('chrome_certificates'):
        if chrome_certificate.key_identifier_value == root_certificate.key_identifier_value:
            certificate_data.update({
                'in_chrome': True
            })
    for edge_certificate in CERTIFICATES.get('edge_certificates'):
        if edge_certificate.key_identifier_value == root_certificate.key_identifier_value:
            certificate_data.update({
                'in_edge': True
            })
    certificate_data['name'] = root_certificate.subject.human_friendly
    return certificate_data

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


def file_to_certificate_object_list(filename=None):
    if filename is None:
        return []
    certificates_list = []
    with open(f'./certificates/{filename}', 'rb') as f:
        for _, _, der_bytes in pem.unarmor(f.read(), multiple=True):
            certificates_list.append(Certificate.load(der_bytes))

    return certificates_list


def load_certificates():
    if CERTIFICATES.get('has_certificates'):
        return
    CERTIFICATES.update({
        'mozilla_certificates': file_to_certificate_object_list('mozilla_certificates.txt'),
        'chrome_certificates': file_to_certificate_object_list('chrome_certificates.txt'),
        'edge_certificates': file_to_certificate_object_list('edge_certificates.txt'),
        'has_certificates': True,
    })
    
@app.route('/index2')
def signout():
    session.clear()
    return redirect('/')

@app.route('/show_trust/<navegator>')
def show_trusts(navegator):
    print(navegator)
    if navegator == 'mozilla':
        c = CERTIFICATES.get('mozilla_certificates')
    elif navegator == 'chrome':
        c = CERTIFICATES.get('chrome_certificates')
    else:
        c = CERTIFICATES.get('edge_certificates')
    for i in c:
        try:
            print("-"*10)
            print(i.subject.human_friendly)
            print(i.serial_number)
            print(i.not_valid_before, i.not_valid_after)
            print(i.public_key.algorithm, i.public_key.bit_size)
            print(i.sha1_fingerprint)
            print(i.key_usage_value.native)
        except Exception as e:
            print("ERROR")
    return render_template('show_trust_by_navegator.html', navegator=navegator, c = c)


@app.route('/', methods=['GET', 'POST'])
def index():
    login_form = URLForm()
    urls = session.get('urls') if type(session.get('urls')) is list else [session.get('urls')]
    context = {
        'login_form': login_form,
        'urls':urls,
    }
    if login_form.validate_on_submit():
        urls = login_form.url.data
        file = login_form.file.data
        session.clear()
        if urls:
            if not verified_https(urls):
                flash("La URL no satisface los requisitos, revisa que tenga el formato https")
                return redirect('/')
        if file:
            urls = validate_file(file)
        session['urls']=urls
        return redirect('/')
    for each_url in urls:
        trust_level = get_relevant_certificate_data(each_url)
        print(trust_level)
    return render_template('index.html', **context)





if __name__=='__main__':
    app.jinja_env.globals.update(get_relevant=get_relevant_certificate_data)
    app.config['WTF_CSRF_ENABLED']= False
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['ENV']='development'
    app.config['SECRET_KEY']='KEY_SECRET'
    load_certificates()
    app.run(debug=True)
