.PHONY: test deploy

ENV ?= staging

test:
	python3 -m unittest discover -s tests -v

deploy:
	scripts/deploy.sh $(ENV)
