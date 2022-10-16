from oscrypto import tls
from certvalidator import CertificateValidator, errors
from certvalidator.path import ValidationPath
from asn1crypto.x509 import Certificate, Name

session = tls.TLSSession(manual_validation=True)
try:
    connection = tls.TLSSocket('meet.google.com', 443, session=session)
except Exception as e:
    print("ppinch")

try:
    validator = CertificateValidator(connection.certificate, connection.intermediates)
    result = validator.validate_tls(connection.hostname)
    # cert_1 = result.__getitem__(0)
    # cert_2 = result.__getitem__(1)
    # cert_3 = result.__getitem__(2)

    for cert in result:
        print(cert.subject.human_friendly)

    # print(hex(cert_1.serial_number), hex(cert_2.serial_number), hex(cert_3.serial_number))
except (errors.PathValidationError):
    print("The certificate did not match the hostname, or could not be otherwise validated")
