from oscrypto import tls
from certvalidator import CertificateValidator, errors

session = tls.TLSSession(manual_validation=True)
try:
    connection = tls.TLSSocket('meet.google.com', 443, session=session)
except Exception as e:
    print("ppinch")

try:
    validator = CertificateValidator(connection.certificate, connection.intermediates)
    result = validator.validate_tls(connection.hostname)
    cert_1 = result._getitem_(0)
    cert_2 = result._getitem_(1)
    cert_3 = result._getitem_(2)
    print(hex(cert_1.serial_number), hex(cert_2.serial_number), hex(cert_3.serial_number))
except (errors.PathValidationError):
    print("The certificate did not match the hostname, or could not be otherwise validated")
