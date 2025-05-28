from flask import Flask, request, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate
from config import Config
from datetime import datetime, timezone
from flask import flash
from asn1crypto import tsp, cms, algos
from asn1crypto import x509 as asn1_x509
from cryptography.hazmat.primitives.asymmetric import padding
import os
import requests

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)

# Import models after db initialization
from models import Timestamp

# Load TSA credentials
with open(Config.TSA_CERT_PATH, 'rb') as f:
    tsa_cert = load_pem_x509_certificate(f.read())

with open(Config.TSA_KEY_PATH, 'rb') as f:
    tsa_key = load_pem_private_key(f.read(), password=None)


# Routes remain the same until the timestamp endpoint
@app.route('/')
def home():
    return redirect(url_for('dashboard'))

# Add to navigation routes (before dashboard)
@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        file = request.files.get('file')
        if not file or file.filename == '':
            flash('Please select a file')
            return redirect(url_for('upload_file'))

        try:
            # Calculate file hash
            digest = hashes.Hash(hashes.SHA256())
            data = file.read()
            digest.update(data)
            file_hash = digest.finalize()

            # Create timestamp request
            tsp_request = tsp.TimeStampReq({
                'version': 1,
                'message_imprint': tsp.MessageImprint({
                    'hash_algorithm': algos.DigestAlgorithm({'algorithm': 'sha256'}),
                    'hashed_message': file_hash
                }),
                'cert_req': True
            })

            # Send to our own timestamp endpoint
            response = requests.post(
                url_for('handle_timestamp_request', _external=True),
                data=tsp_request.dump(),
                headers={'Content-Type': 'application/timestamp-query'}
            )

            if response.status_code == 200:
                flash('Timestamp created successfully!', 'success')
            else:
                flash(f'Error creating timestamp: {response.content.decode()}', 'danger')

            return redirect(url_for('dashboard'))

        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')
            return redirect(url_for('upload_file'))

    return render_template('upload.html')

@app.route('/dashboard')
def dashboard():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    timestamps = Timestamp.query.order_by(Timestamp.created_at.desc()).paginate(page=page, per_page=per_page)
    return render_template('dashboard.html', timestamps=timestamps)


@app.route('/timestamp/<int:timestamp_id>')
def timestamp_detail(timestamp_id):
    timestamp = Timestamp.query.get_or_404(timestamp_id)
    return render_template('timestamp_detail.html', timestamp=timestamp)


@app.route('/verify', methods=['GET', 'POST'])
def verify_timestamp_web():
    if request.method == 'POST':
        if 'verify_by_id' in request.form:
            timestamp_id = request.form.get('timestamp_id')
            if not timestamp_id:
                return render_template('verify.html', error="Please provide a timestamp ID")
            return redirect(url_for('timestamp_detail', timestamp_id=timestamp_id))

        if 'verify_by_file' in request.form:
            file = request.files.get('file')
            if not file or file.filename == '':
                return render_template('verify.html', error="Please select a file")

            try:
                digest = hashes.Hash(hashes.SHA256())
                data = file.read()
                digest.update(data)
                file_hash = digest.finalize()

                timestamp = Timestamp.query.filter_by(data_hash=file_hash).first()
                if timestamp:
                    return redirect(url_for('timestamp_detail', timestamp_id=timestamp.id))
                return render_template('verify.html', error="No matching timestamp found")
            except Exception as e:
                return render_template('verify.html', error=str(e))

    return render_template('verify.html')


@app.route('/timestamp', methods=['POST'])
def handle_timestamp_request():
    """RFC3161 Timestamp Protocol Endpoint"""
    try:
        tsp_request = tsp.TimeStampReq.load(request.get_data())
    except ValueError:
        return construct_error_response(tsp.PKIFailureInfo({'bad_request'})), 400

    # Validate hash algorithm
    if tsp_request['message_imprint']['hash_algorithm']['algorithm'].native != 'sha256':
        return construct_error_response(tsp.PKIFailureInfo({'bad_alg'})), 400

    hashed_message = tsp_request['message_imprint']['hashed_message'].native

    try:
        # Create timestamp token
        timestamp_token = create_timestamp_token(hashed_message)

        # Store in database
        new_entry = Timestamp(
            data_hash=hashed_message,
            timestamp_token=timestamp_token.dump()
        )
        db.session.add(new_entry)
        db.session.commit()

        # Build successful response
        tsp_response = tsp.TimeStampResp({
            'status': tsp.PKIStatusInfo({
                'status': 0
            }),
            'time_stamp_token': timestamp_token
        })

        return tsp_response.dump(), 200, {'Content-Type': 'application/timestamp-reply'}


    except Exception as e:
        return construct_error_response(tsp.PKIFailureInfo({'system_failure'})), 500


def create_timestamp_token(hashed_message):
    """Create CMS signed timestamp token"""
    signed_time = datetime.now(timezone.utc).replace(microsecond=0)

    der_cert = tsa_cert.public_bytes(encoding=serialization.Encoding.DER)
    asn1_cert = asn1_x509.Certificate.load(der_cert)
    issuer = asn1_cert.issuer

    # TSTInfo structure
    tst_info = tsp.TSTInfo({
        'version': 1,
        'policy': tsp.ObjectIdentifier('1.3.6.1.4.1.4146.2.3'),
        'message_imprint': tsp.MessageImprint({
            'hash_algorithm': algos.DigestAlgorithm({'algorithm': 'sha256'}),
            'hashed_message': hashed_message
        }),
        'serial_number': int.from_bytes(os.urandom(4), 'big'),
        'gen_time': signed_time,
        'accuracy': tsp.Accuracy({'seconds': 1}),
        'ordering': False
    })

    # SignerInfo structure
    signer_info = cms.SignerInfo({
        'version': 'v1',
        'sid': cms.SignerIdentifier({
            'issuer_and_serial_number': cms.IssuerAndSerialNumber({
                'issuer': issuer,  # Use converted asn1crypto Name object
                'serial_number': tsa_cert.serial_number
            })
        }),
        'digest_algorithm': algos.DigestAlgorithm({'algorithm': 'sha256'}),
        'signature_algorithm': algos.SignedDigestAlgorithm({'algorithm': 'rsassa_pkcs1v15'}),
        'signature': tsa_key.sign(
            tst_info.dump(),
            algorithm=hashes.SHA256(),
            padding=padding.PKCS1v15()
        )
    })

    # SignedData structure
    signed_data = cms.SignedData({
        'version': 'v3',
        'digest_algorithms': cms.DigestAlgorithms([algos.DigestAlgorithm({'algorithm': 'sha256'})]),
        'encap_content_info': cms.EncapsulatedContentInfo({
            'content_type': 'tst_info',
            'content': tst_info
        }),
        'certificates': [cms.CertificateChoices({'certificate': asn1_cert})],
        'signer_infos': cms.SignerInfos([signer_info])
    })

    return cms.ContentInfo({
        'content_type': 'signed_data',
        'content': signed_data
    })


def construct_error_response(failure_info):
    tsp_response = tsp.TimeStampResp({
        'status': tsp.PKIStatusInfo({
            'status': tsp.PKIStatus(2),
            'fail_info': failure_info
        })
    })
    return tsp_response.dump(), 400, {'Content-Type': 'application/timestamp-reply'}


@app.route('/api/verify/<int:timestamp_id>', methods=['GET'])
def verify_timestamp_api(timestamp_id):
    """Verification Endpoint (for demonstration)"""
    entry = Timestamp.query.get_or_404(timestamp_id)
    return {
        'id': entry.id,
        'data_hash': entry.data_hash.hex(),
        'timestamp_token': entry.timestamp_token.hex(),
        'created_at': entry.created_at.isoformat()
    }


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(ssl_context='adhoc', host='0.0.0.0', port=5000)