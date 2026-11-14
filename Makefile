build:
	mkdir -p build bin && gfortran -O2 -Wall -o bin/cvss31 src/cvss.f90 src/main.f90 -J build

test: build
	mkdir -p build && gfortran -O2 -Wall -o build/test tests/test.f90 src/cvss.f90 -J build && ./build/test

sample: build
	mkdir -p docs site
	./bin/cvss31 --file examples/vectors.txt > docs/sample-output.txt; true
	./bin/cvss31 --file examples/vectors.txt --tsv > docs/sample-output.tsv; true
	python3 scripts/site.py docs/sample-output.tsv site/index.html "cvss31" "CVSS v3.1 base score calculator and batch triage. Fortran." "Fictional finding IDs with real CVSS vectors from public CVEs."
