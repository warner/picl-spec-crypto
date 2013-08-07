
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
