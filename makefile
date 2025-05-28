generate-certs:
	openssl genpkey -algorithm RSA -out tsa_key.pem
	openssl req -new -x509 -key tsa_key.pem -out tsa_cert.pem -days 365 -subj "/CN=Timestamp Authority"

init-db:
	flask shell -c 'from app import db; db.create_all()'

run:
	flask run --cert=adhoc

.PHONY: generate-certs init-db run