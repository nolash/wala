all:
	cargo -v --bin wala --all-features --release

rustup:
	rustup run 1.67 cargo build -v --bin wala --all-features --release

debug:
	rustup run 1.67 cargo build -v --all-features

test:
	rustup run 1.67 cargo test -v --all-features

doc:
	-asciidoc -b docbook5 README.adoc 
	-pandoc -f docbook -t gfm -o README.md README.xml
	-pandoc -f docbook -t plain -o README.txt README.xml
	rm -vf README.xml

clean:
	rm -vrf target/

.PHONY: clean
