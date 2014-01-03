
help:
	@echo "run: make venv deps"
	@echo "then ./venv/bin/python demo-client.py create email@example.org pw"
	@echo " (and click verification email link)"
	@echo " ./venv/bin/python demo-client.py login email@example.org pw"
	@echo " ./venv/bin/python demo-client.py login-with-keys email@example.org pw"
	@echo " ./venv/bin/python demo-client.py change-password email@example.org pw newpw"
	@echo " forgot-password flow:"
	@echo "  ./venv/bin/python demo-client.py forgotpw-send email@example.org"
	@echo "  ./venv/bin/python demo-client.py forgotpw-resend email@example.org token"
	@echo "  ./venv/bin/python demo-client.py forgotpw-submit email@example.org token code newerpw"
	@echo " destroy-account flow:"
	@echo " ./venv/bin/python demo-client.py destroy email@example.org newerpw"

venv:
	virtualenv venv

.deps: venv
	venv/bin/pip install scrypt
	venv/bin/pip install requests
	venv/bin/pip install PyHawk
	touch .deps
.PHONY: deps
deps: .deps

vectors: .deps
	venv/bin/python picl-crypto.py
