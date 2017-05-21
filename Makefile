DESTDIR=/
PROJECT=manpkid
VERSION=0.2
RELEASE :=$(shell ls -1 dist/*.noarch.rpm 2>/dev/null | wc -l )
HASH	:=$(shell git rev-parse HEAD )
DISTRO=precise
PYTHONPATH ?="./:./manpki"

all:
	@echo "make run      - Run manpkid from this directory"
	@echo "make config   - Run a simple configuration CLI program"
	@echo "make docs     - Build docs"
	@echo "make sdist    - Create source package"
	@echo "make bdist    - Create binary package"
	@echo "make pypi     - Update PyPI package"
	@echo "make install  - Install on local system"
	@echo "make develop  - Install on local system in development mode"
	@echo "make rpm      - Generate a rpm package"
	@echo "make deb      - Generate a deb package"
	@echo "make sdeb     - Generate a deb source package"
	@echo "make tar      - Generate a tar ball"
	@echo "make clean    - Get rid of scratch and byte files"

run:
	PYTHONPATH=$(PYTHONPATH) ./bin/manpkid 

test:
	tests/manpki_tests.py

test_with_lib:
	PYTHONPATH=$(PYTHONPATH) tests/manpki_tests.py

env:
	PYTHONPATH=$(PYTHONPATH) python -c "import manpki.config; manpki.config.setup()"
	PYTHONPATH=$(PYTHONPATH) python tools/manageUser.py -a -u $(USER) -g admin

docs: version
	PYTHONPATH=$(PYTHONPATH) $(MAKE) -C ./docs html

sdist: version
	./setup.py sdist

bdist: version
	./setup.py bdist

install: version
	./setup.py install --root $(DESTDIR)

deps: version
	pip install -r requirements.txt

develop: version
	USE_SETUPTOOLS=1 ./setup.py develop

rpm: buildrpm

buildrpm: sdist
	./setup.py bdist_rpm \
		--release=`ls dist/*.noarch.rpm | wc -l` \
		--build-requires='python' \
		--requires='python'

deb: builddeb

sdeb: buildsourcedeb

builddeb: version
	dch --newversion $(VERSION) --distribution unstable --force-distribution -b "Last Commit: $(shell git log -1 --pretty=format:'(%ai) %H %cn <%ce>')"
	dch --release  "new upstream"
	./setup.py sdist
	mkdir -p build
	tar -C build -zxf dist/$(PROJECT)-$(VERSION).tar.gz
	(cd build/$(PROJECT)-$(VERSION) && debuild -us -uc -v$(VERSION))
	@echo "Package is at build/$(PROJECT)_$(VERSION)_all.deb"

buildsourcedeb: version
	dch --newversion $(VERSION)~$(DISTRO) --distribution $(DISTRO) --force-distribution -b "Last Commit: $(shell git log -1 --pretty=format:'(%ai) %H %cn <%ce>')"
	dch --release  "new upstream"
	./setup.py sdist
	mkdir -p build
	tar -C build -zxf dist/$(PROJECT)-$(VERSION).tar.gz
	(cd build/$(PROJECT)-$(VERSION) && debuild -S -sa -v$(VERSION))
	@echo "Source package is at build/$(PROJECT)_$(VERSION)~$(DISTRO)_source.changes"

tar: sdist

clean:
	$(MAKE) -C ./docs clean
	./setup.py clean
	rm -rf dist build MANIFEST .tox *.log
	find . -name '*.pyc' -delete
	rm manpki/VERSION

vertest: version
	echo "${VERSION}"

reltest:
	echo "$(RELEASE)"

distrotest:
	echo ${DISTRO}

pypi: version
	python setup.py sdist upload

localpypi: version
	python setup.py sdist upload -r local

.PHONY: run config docs sdist bdist install rpm buildrpm deb sdeb builddeb buildsourcedeb tar clean cleanws version reltest vertest distrotest pypi test
