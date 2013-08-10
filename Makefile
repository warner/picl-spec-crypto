
help:
	@echo "run: make venv deps"
	@echo "then ./venv/bin/python demo-client.py email@example.org pw create"
	@echo "then ./venv/bin/python demo-client.py email@example.org pw login"
	@echo "then ./venv/bin/python demo-client.py email@example.org pw changepw newpw"
	@echo "then ./venv/bin/python demo-client.py email@example.org newpw login"
	@echo "then ./venv/bin/python demo-client.py email@example.org newpw destroy"

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
