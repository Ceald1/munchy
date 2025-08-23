SHELL := /bin/bash
export WINEARCH = win64
export WINEPREFIX = $(HOME)/.wine_munchy
munchy:
	cross clean
	cross build --target x86_64-pc-windows-gnu --release
	@echo -e "\n\n\n\nrelease in target/x86_64-pc-windows-gnu/release/munchy.exe"

config:
	
	
	@echo "configuring environment...."
	rm -rf ~/.wine_munchy
	wineboot -u
	@echo -e "\n\n\n\n\nconfigure your wine to put win 11"
	winecfg
	winetricks -q riched20 gdiplus
	@echo -e "\n\n\n\nconfigure wine again to add kerberos and the other packages"
	winecfg
	wineboot -u
	

test:
	cross clean
	cross build --target x86_64-pc-windows-gnu --release
	WINEDEBUG=+secur32,+lsa,+kerberos wine target/x86_64-pc-windows-gnu/release/munchy.exe test

	@echo "exit code: $$?"
