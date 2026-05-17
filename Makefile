.PHONY: all release man completions deb docker clean

BIN := target/release/fortibackup

all: release man completions

release:
	cargo build --release --locked

man: release
	@mkdir -p target/man
	$(BIN) manpage | gzip -9n > target/man/fortibackup.1.gz

completions: release
	@mkdir -p target/completions
	$(BIN) completions bash > target/completions/fortibackup.bash
	$(BIN) completions zsh  > target/completions/_fortibackup
	$(BIN) completions fish > target/completions/fortibackup.fish

deb: man completions
	cargo deb --no-build

docker:
	docker build -t fortibackup:$(shell git describe --tags --always --dirty) -t fortibackup:latest .

clean:
	cargo clean
	rm -rf target/man target/completions
