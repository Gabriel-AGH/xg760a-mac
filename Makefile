# Pilote en espace utilisateur pour la clé Wi-Fi Sagem XG-760A (ZyDAS ZD1211)
# sur macOS Intel. Nécessite seulement les « Command Line Tools » d'Apple.

CC      ?= clang
BUILD   := build
CFLAGS  := -std=gnu11 -O2 -g -Wall -Wextra -Wno-unused-parameter \
           -Wno-missing-field-initializers -mmacosx-version-min=10.13 \
           -Icompat -Isrc -Ivendor/zd1211rw
# Les fichiers repris tels quels de Linux ne sont pas écrits pour -Wextra.
VENDOR_CFLAGS := -Wno-unused-function -Wno-sign-compare -Wno-unused-variable
LDFLAGS := -framework IOKit -framework CoreFoundation

VERSION := $(shell sed -n 's/^\#define XG_VERSION "\(.*\)"/\1/p' src/service.h)

VENDOR_SRC := $(wildcard vendor/zd1211rw/*.c)
CORE_SRC   := src/usbdev.c src/log.c src/zd_usb.c
FW_FILES   := $(addprefix firmware/,zd1211_ub zd1211_ur zd1211_uphr \
                zd1211b_ub zd1211b_ur zd1211b_uphr)

VENDOR_OBJ := $(patsubst vendor/zd1211rw/%.c,$(BUILD)/vendor_%.o,$(VENDOR_SRC))
CORE_OBJ   := $(patsubst src/%.c,$(BUILD)/%.o,$(CORE_SRC)) $(BUILD)/fw_data.o
DRIVER_SRC := $(filter-out $(CORE_SRC) src/main.c,$(wildcard src/*.c))
DRIVER_OBJ := $(patsubst src/%.c,$(BUILD)/%.o,$(DRIVER_SRC))

TESTS := $(patsubst tests/%.c,$(BUILD)/%,$(wildcard tests/*.c))

.PHONY: all tests clean
all: $(BUILD)/xg760a app

tests: $(TESTS)

$(BUILD):
	@mkdir -p $(BUILD)

$(BUILD)/fw_data.c: $(FW_FILES) tools/mkfw.sh | $(BUILD)
	sh tools/mkfw.sh firmware $@

$(BUILD)/fw_data.o: $(BUILD)/fw_data.c src/fw.h
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/vendor_%.o: vendor/zd1211rw/%.c $(wildcard src/*.h compat/*.h vendor/zd1211rw/*.h) | $(BUILD)
	$(CC) $(CFLAGS) $(VENDOR_CFLAGS) -c $< -o $@

$(BUILD)/%.o: src/%.c $(wildcard src/*.h compat/*.h vendor/zd1211rw/*.h) | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/xg760a: $(BUILD)/main.o $(DRIVER_OBJ) $(CORE_OBJ) $(VENDOR_OBJ)
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

# Programmes de mise au point : chacun est lié avec tout sauf main.o.
$(BUILD)/%: tests/%.c $(DRIVER_OBJ) $(CORE_OBJ) $(VENDOR_OBJ) $(wildcard src/*.h compat/*.h)
	$(CC) $(CFLAGS) $< $(DRIVER_OBJ) $(CORE_OBJ) $(VENDOR_OBJ) $(LDFLAGS) -o $@

# Essai de bout en bout sans radio : le vrai code de la station face à une
# clé et un point d'accès simulés (tests/simap.c remplace src/device.c).
$(BUILD)/simap: tests/simap.c $(BUILD)/wlan.o $(BUILD)/wpa.o $(BUILD)/crypto.o $(BUILD)/ministack.o $(BUILD)/log.o
	$(CC) $(CFLAGS) $^ -o $@

# --- vérifications sans matériel ---------------------------------------------
# Vecteurs officiels, captures réelles rejouées, pile complète face à un
# point d'accès simulé. Ne touche ni à la clé ni au réseau.
.PHONY: check
check: $(BUILD)/crypto_test $(BUILD)/pcapcheck $(BUILD)/simap
	$(BUILD)/crypto_test
	$(BUILD)/pcapcheck tests/captures/wpa-Induction.pcap Induction
	$(BUILD)/pcapcheck tests/captures/wpa2-psk-ccmp-tkip.pcapng 12345678
	@for s in ccmp tkip-group wpa2-tkip wpa1 open wrongpass scan panne deauth; do \
		$(BUILD)/simap $$s > $(BUILD)/simap-$$s.log 2>&1; r=$$?; \
		grep -E '^(ok|ÉCHEC|===)' $(BUILD)/simap-$$s.log; \
		[ $$r -eq 0 ] || exit 1; \
	done
	@echo "Toutes les vérifications sans matériel passent."

# --- application de barre de menus -------------------------------------------
# Objective-C compilé par clang : ne demande ni Xcode ni Swift.
APP_DIR := $(BUILD)/Wi-Fi XG-760A.app
APP_STAMP := $(BUILD)/app.stamp

.PHONY: app
app: $(APP_STAMP)

$(APP_STAMP): app/main.m app/Info.plist src/client.c src/crypto.c $(wildcard src/*.h) | $(BUILD)
	rm -rf "$(APP_DIR)"
	mkdir -p "$(APP_DIR)/Contents/MacOS"
	sed 's/@VERSION@/$(VERSION)/' app/Info.plist > "$(APP_DIR)/Contents/Info.plist"
	$(CC) -fobjc-arc -O2 -Wall -mmacosx-version-min=10.13 -Isrc -Icompat \
		app/main.m src/client.c src/crypto.c -framework Cocoa \
		-o "$(APP_DIR)/Contents/MacOS/Wi-Fi XG-760A"
	touch $@

# --- installeur -------------------------------------------------------------
# « make pkg » produit build/XG760A-<version>.pkg, à copier sur un autre Mac
# Intel et à ouvrir d'un double-clic. Le paquet ne dépose ses fichiers que
# dans /Library/Application Support/XG760A ; son script de fin d'installation
# met en place le service de démarrage et la commande xg760a.
PKG     := $(BUILD)/XG760A-$(VERSION).pkg
STAGE   := $(BUILD)/pkg/racine

.PHONY: pkg
pkg: $(PKG)

$(PKG): $(BUILD)/xg760a $(APP_STAMP) $(wildcard packaging/* packaging/scripts/* packaging/resources/*) COPYING LISEZMOI.md
	rm -rf $(BUILD)/pkg
	mkdir -p $(STAGE) $(BUILD)/pkg/ressources $(BUILD)/pkg/composants
	cp $(BUILD)/xg760a $(STAGE)/xg760a
	strip -x $(STAGE)/xg760a
	cp packaging/local.xg760a.plist packaging/local.xg760a.menu.plist \
		packaging/desinstaller.command $(STAGE)/
	cp LISEZMOI.md $(STAGE)/LISEZMOI.md
	cp COPYING $(STAGE)/LICENCE-GPL.txt
	cp -R "$(APP_DIR)" $(STAGE)/
	strip -x "$(STAGE)/Wi-Fi XG-760A.app/Contents/MacOS/Wi-Fi XG-760A"
	chmod 755 $(STAGE)/xg760a $(STAGE)/desinstaller.command
	pkgbuild --quiet --root $(STAGE) --identifier local.xg760a.pkg \
		--version $(VERSION) --ownership recommended \
		--install-location "/Library/Application Support/XG760A" \
		--component-plist packaging/composants.plist \
		--scripts packaging/scripts $(BUILD)/pkg/composants/xg760a-composant.pkg
	cp packaging/resources/*.html $(BUILD)/pkg/ressources/
	cp COPYING $(BUILD)/pkg/ressources/licence.txt
	sed 's/@VERSION@/$(VERSION)/' packaging/distribution.xml > $(BUILD)/pkg/distribution.xml
	productbuild --quiet --distribution $(BUILD)/pkg/distribution.xml \
		--resources $(BUILD)/pkg/ressources \
		--package-path $(BUILD)/pkg/composants $@
	@echo "Installeur: $@"

clean:
	rm -rf $(BUILD)
