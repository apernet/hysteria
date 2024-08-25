import argparse
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption


def create_key():
    return ec.generate_private_key(ec.SECP256R1())


def create_certificate(cert_type, subject, issuer, private_key, public_key, dns_san=None):
    serial_number = x509.random_serial_number()
    not_valid_before = datetime.datetime.now(datetime.UTC)
    not_valid_after = not_valid_before + datetime.timedelta(days=365)

    subject_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, subject.get('C', 'ZZ')),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject.get('O', 'No Organization')),
        x509.NameAttribute(NameOID.COMMON_NAME, subject.get('CN', 'No CommonName')),
    ])
    issuer_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, issuer.get('C', 'ZZ')),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, issuer.get('O', 'No Organization')),
        x509.NameAttribute(NameOID.COMMON_NAME, issuer.get('CN', 'No CommonName')),
    ])
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject_name)
    builder = builder.issuer_name(issuer_name)
    builder = builder.public_key(public_key)
    builder = builder.serial_number(serial_number)
    builder = builder.not_valid_before(not_valid_before)
    builder = builder.not_valid_after(not_valid_after)
    if cert_type == 'root':
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
    elif cert_type == 'intermediate':
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=0), critical=True
        )
    elif cert_type == 'leaf':
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
    else:
        raise ValueError(f'Invalid cert_type: {cert_type}')
    if dns_san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(d) for d in dns_san.split(',')]),
            critical=False
        )
    return builder.sign(private_key=private_key, algorithm=hashes.SHA256())


def main():
    parser = argparse.ArgumentParser(description='Generate HTTPS server certificate.')
    parser.add_argument('--ca', required=True,
                        help='Path to write the X509 CA certificate in PEM format')
    parser.add_argument('--cert', required=True,
                        help='Path to write the X509 certificate in PEM format')
    parser.add_argument('--key', required=True,
                        help='Path to write the private key in PEM format')
    parser.add_argument('--dnssan', required=False, default=None,
                        help='Comma-separated list of DNS SANs')
    parser.add_argument('--type', required=True, choices=['selfsign', 'fullchain'],
                        help='Type of certificate to generate')

    args = parser.parse_args()

    key = create_key()
    public_key = key.public_key()

    if args.type == 'selfsign':
        subject = {"C": "ZZ", "O": "Certificate", "CN": "Certificate"}
        cert = create_certificate(
            cert_type='root',
            subject=subject,
            issuer=subject,
            private_key=key,
            public_key=public_key,
            dns_san=args.dnssan)
        with open(args.ca, 'wb') as f:
            f.write(cert.public_bytes(Encoding.PEM))
        with open(args.cert, 'wb') as f:
            f.write(cert.public_bytes(Encoding.PEM))
        with open(args.key, 'wb') as f:
            f.write(
                key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()))

    elif args.type == 'fullchain':
        ca_key = create_key()
        ca_public_key = ca_key.public_key()
        ca_subject = {"C": "ZZ", "O": "Root CA", "CN": "Root CA"}
        ca_cert = create_certificate(
            cert_type='root',
            subject=ca_subject,
            issuer=ca_subject,
            private_key=ca_key,
            public_key=ca_public_key)

        intermediate_key = create_key()
        intermediate_public_key = intermediate_key.public_key()
        intermediate_subject = {"C": "ZZ", "O": "Intermediate CA", "CN": "Intermediate CA"}
        intermediate_cert = create_certificate(
            cert_type='intermediate',
            subject=intermediate_subject,
            issuer=ca_subject,
            private_key=ca_key,
            public_key=intermediate_public_key)

        leaf_subject = {"C": "ZZ", "O": "Leaf Certificate", "CN": "Leaf Certificate"}
        cert = create_certificate(
            cert_type='leaf',
            subject=leaf_subject,
            issuer=intermediate_subject,
            private_key=intermediate_key,
            public_key=public_key,
            dns_san=args.dnssan)

        with open(args.ca, 'wb') as f:
            f.write(ca_cert.public_bytes(Encoding.PEM))
        with open(args.cert, 'wb') as f:
            f.write(cert.public_bytes(Encoding.PEM))
            f.write(intermediate_cert.public_bytes(Encoding.PEM))
        with open(args.key, 'wb') as f:
            f.write(
                key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()))


if __name__ == "__main__":
    main()
