GO	= go
EXT	=

PLAKAR	= plakar
VERSION	= v1.1.1

all: build

build:
	${GO} build -v -o remarkable-importer${EXT} ./cmd/importer

package: build
	rm -f remarkable_${VERSION}_*.ptar
	${PLAKAR} pkg create ./manifest.yaml ${VERSION}

uninstall:
	-${PLAKAR} pkg rm remarkable

install: package
	${PLAKAR} pkg add ./remarkable_${VERSION}_*.ptar

reinstall: uninstall install

test:
	${GO} test -v ./...

check: test
	${GO} vet ./...

clean:
	rm -f remarkable-importer${EXT} remarkable_*.ptar

.PHONY: all build package uninstall install reinstall test check clean
