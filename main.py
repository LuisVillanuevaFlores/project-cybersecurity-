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
from datetime import date,datetime,time,timedelta

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
    url_pattern = "^(http|https):\\/\\/(?:www\\.)?[-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{1,6}\\b(?:[-a-zA-Z0-9()@:%_\\+.~#?&\\/=]*)$"
    match = re.match(url_pattern, url)
    if match:
        print(match)
        return match
    else:
        flash(f'La URL {url} no es de un sitio válido')

def get_relevant_certificate_data(url):
    if url in [None, '']:
        return None
    host = re.search(r'https?://([^/?:]*)', url).group(1)
    try:
        connection = tls.TLSSocket(host, 443, session=tls.TLSSession(manual_validation=True))
    except Exception as e:
        return None
    certificate_data = dict(
        in_mozilla=False,
        in_chrome=False,
        in_edge=False,
        mozilla_trust_level=3,
        chrome_trust_level=3,
        edge_trust_level=3
    )

    validator = CertificateValidator(connection.certificate, connection.intermediates)

    try:
        certification_chain = validator.validate_tls(connection.hostname)
    except Exception as e:
        flash(f'No se encontró un certificado válido para la url: {url}, revisarla')
        certificate_data.update({
            'cadena': []
        })
        return certificate_data
    root_certificate = certification_chain[0]

    cadena_de_certificacion = []

    for certificate in certification_chain:
        cadena_de_certificacion.append({
            'name': certificate.subject.human_friendly.replace('; ', ', ').split(",",1)[0],
            'desde': certificate.not_valid_before.date(),
            'hasta': certificate.not_valid_after.date(),
            'algoritmo': certificate.public_key.algorithm.upper(),
            'tamanhollave': certificate.public_key.bit_size,
            'uso_de_llave': certificate.key_usage_value.native,
            'sha1': certificate.sha1_fingerprint,
            'serial': certificate.serial_number
        })
    certificate_data.update({
        'cadena': cadena_de_certificacion
    })

    for mozilla_certificate in CERTIFICATES.get('mozilla_certificates'):
        if mozilla_certificate.key_identifier_value == root_certificate.key_identifier_value:
            certificate_data.update({
                'in_mozilla': True, 
                'mozilla_trust_level': 1 if 'https:' in url else 2
                
            })
        
    for chrome_certificate in CERTIFICATES.get('chrome_certificates'):
        if chrome_certificate.key_identifier_value == root_certificate.key_identifier_value:
           
            certificate_data.update({
                'in_chrome': True,
                'chrome_trust_level': 1 if 'https:' in url else 2
            })
    for edge_certificate in CERTIFICATES.get('edge_certificates'):
        if edge_certificate.key_identifier_value == root_certificate.key_identifier_value:
            certificate_data.update({
                    'in_edge': True,
                    'edge_trust_level': 1 if 'https:' in url else 2
            })
    certificate_data['name'] = root_certificate.subject.human_friendly
    print(certificate_data)
    return certificate_data

def validate_file(file):
    urls = []
    if file.content_type == 'text/plain':
        file.save(os.path.join(os.path.abspath(os.path.dirname(__file__)),secure_filename(file.filename)))
        with open(file.filename,'r') as file:
            for line in file:
                # You can verified if a url is https format with verified_https function
                if verified_https(line):
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

def sort_certificates_last_five(certificates):
    nuevos = []
    for certificate in certificates:
        nuevos.append((certificate.not_valid_before.date(), certificate.subject.human_friendly.replace('; ', ', ').split(",",1)[0]))
    nuevos.sort()
    print(nuevos[-5:])
    return nuevos[-5:]

def sort_certificates_most_aged(certificates):
    certificados_longevos = []
    for certificate in certificates:
        x=certificate.not_valid_after.date() - certificate.not_valid_before.date()
        print(type(x))
        certificados_longevos.append((f'{x.days//365} Años' , certificate.subject.human_friendly.replace('; ', ', ').split(",",1)[0]))
    certificados_longevos.sort()



    
    print(certificados_longevos[-5:])
    return certificados_longevos[-5:]


@app.route('/index2')
def signout():
    session.clear()
    return redirect('/')

@app.route('/show_trust/<navegator>')
def show_trusts(navegator):
    if navegator == 'mozilla':
        c = CERTIFICATES.get('mozilla_certificates')
    elif navegator == 'chrome':
        c = CERTIFICATES.get('chrome_certificates')
    else:
        c = CERTIFICATES.get('edge_certificates')

    cd_nuevos = sort_certificates_last_five(c)
    cd_longevos = sort_certificates_most_aged(c)
    return render_template('show_trust_by_navegator.html', navegator=navegator, c = c, cd_nuevos=cd_nuevos,cd_longevos=cd_longevos)


@app.route('/', methods=['GET', 'POST'])
def index():
    login_form = URLForm()
    urls = session.get('urls') if session.get('urls') else []
    context = {
        'login_form': login_form,
        'urls':urls,
    }
    if login_form.validate_on_submit():
        file = login_form.file.data
        url = login_form.url.data
        if url and verified_https(url):
            urls.append(url)
        elif file:
            urls += validate_file(file)
        else:
            flash('Debe ingresar una URL o cargar un archivo con URLS')
        session['urls']=urls
        return redirect('/')
    return render_template('index.html', **context)


app.jinja_env.globals.update(get_relevant=get_relevant_certificate_data)
app.jinja_env.globals.update(enumerate = enumerate)
app.config['WTF_CSRF_ENABLED']= False
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SECRET_KEY']='KEY_SECRET'
load_certificates()


if __name__=='__main__':
    app.config['ENV']='development'
    app.run(debug=True)
