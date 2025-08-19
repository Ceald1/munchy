SHELL := /bin/bash
munchy:
	cross clean
	cross build --target x86_64-pc-windows-gnu --release
	@echo "\n\n\n\nrelease in target/x86_64-pc-windows-gnu/release/munchy.exe"

test:
	cross clean
	cross build --target x86_64-pc-windows-gnu --release
	wine target/x86_64-pc-windows-gnu/release/munchy.exe test

	@echo "exit code: $$?"
