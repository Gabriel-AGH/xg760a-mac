// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Gabriel-AGH
//
// « Wi-Fi XG-760A » : petite application de barre de menus pour piloter le
// pilote xg760a sans passer par le Terminal. Elle ne touche pas à la clé :
// elle envoie des requêtes au service par son socket local, exactement
// comme la commande xg760a.
//
//   "Wi-Fi XG-760A" --etat        affiche l'état reçu du service et quitte
//   "Wi-Fi XG-760A" --recherche   affiche les réseaux à portée et quitte

#import <Cocoa/Cocoa.h>

#include "crypto.h"
#include "service.h"

// MARK: - dialogue avec le service

/// Envoie une ligne au service ; nil s'il est injoignable.
static NSString *Ask(NSString *line)
{
	/* XG760A_SOCKET : uniquement pour la mise au point */
	const char *path = getenv("XG760A_SOCKET") ?: XG_SOCKET_PATH;
	char *reply = service_request(path, line.UTF8String);
	NSString *text;

	if (!reply)
		return nil;
	text = [NSString stringWithUTF8String:reply];
	if (!text)
		text = [[NSString alloc] initWithCString:reply
						encoding:NSISOLatin1StringEncoding];
	free(reply);
	return text ?: @"";
}

/// Réponse « clé=valeur » d'une requête STATUS ; nil si le service est arrêté.
static NSDictionary<NSString *, NSString *> *FetchStatus(void)
{
	NSString *reply = Ask(@"STATUS");
	NSMutableDictionary *fields;

	if (!reply)
		return nil;
	fields = [NSMutableDictionary dictionary];
	for (NSString *line in [reply componentsSeparatedByString:@"\n"]) {
		NSRange eq = [line rangeOfString:@"="];

		if (eq.location != NSNotFound)
			fields[[line substringToIndex:eq.location]] =
				[line substringFromIndex:eq.location + 1];
	}
	return fields;
}

/// Nom lisible d'un réseau à partir de son écriture hexadécimale.
static NSString *SsidText(NSString *hexName)
{
	uint8_t bytes[33];
	int len = hex_decode(hexName.UTF8String, bytes, 32);
	NSString *text;

	if (len <= 0)
		return @"(nom masqué)";
	for (int i = 0; i < len; i++)
		if (bytes[i] < 0x20 || bytes[i] == 0x7f)
			bytes[i] = '?';
	text = [[NSString alloc] initWithBytes:bytes
					length:(NSUInteger)len
				      encoding:NSUTF8StringEncoding];
	if (!text)
		text = [[NSString alloc] initWithBytes:bytes
						length:(NSUInteger)len
					      encoding:NSISOLatin1StringEncoding];
	return text ?: @"?";
}

/// Clé WPA (64 chiffres hexadécimaux) dérivée de la phrase secrète.
static NSString *WpaKey(NSString *passphrase, NSString *hexName)
{
	uint8_t ssid[32], pmk[32];
	char out[65];
	int len = hex_decode(hexName.UTF8String, ssid, 32);

	if (len <= 0 ||
	    wpa_passphrase_to_pmk(passphrase.UTF8String, ssid, (size_t)len, pmk))
		return nil;
	hex_encode(pmk, 32, out);
	memset(pmk, 0, sizeof(pmk));
	return @(out);
}

static BOOL IsConnected(NSDictionary *st)
{
	return [st[@"state"] intValue] == WLAN_CONNECTED;
}

/// Une ligne qui résume l'état, pour l'en-tête du menu et l'infobulle.
static NSString *Summary(NSDictionary *st)
{
	int state = [st[@"state"] intValue];
	NSString *name = SsidText(st[@"ssid"] ?: @"");

	if (!st)
		return @"Service du pilote arrêté";
	if ([st[@"device"] length] == 0)
		return @"Clé non branchée";
	switch (state) {
	case WLAN_CONNECTED:
		return [NSString stringWithFormat:
			@"Connecté à « %@ » · %g Mbit/s · signal %@ %%", name,
			[st[@"tx_rate"] doubleValue] / 2, st[@"signal"]];
	case WLAN_SCANNING:
		return @"Recherche des réseaux…";
	case WLAN_AUTHENTICATING:
	case WLAN_ASSOCIATING:
	case WLAN_HANDSHAKE:
		return [NSString stringWithFormat:@"Connexion à « %@ »…", name];
	default:
		return [st[@"autoconnect"] isEqualToString:@"0"] ? @"Déconnecté" :
								    @"Non connecté";
	}
}

static NSString *Bars(int signal)
{
	int n = signal >= 55 ? 4 : signal >= 40 ? 3 : signal >= 25 ? 2 :
		signal >= 12 ? 1 : 0;

	return [[@"" stringByPaddingToLength:(NSUInteger)n
				  withString:@"●"
			     startingAtIndex:0]
		stringByPaddingToLength:4 withString:@"○" startingAtIndex:0];
}

/// Réseaux à portée, le plus fort d'abord, un seul par nom. Chaque entrée :
/// name (hexadécimal), signal, channel, usable, security.
static NSArray<NSDictionary *> *ScanNetworks(void)
{
	NSString *reply = Ask(@"SCAN");
	NSMutableArray *list;
	NSMutableSet *seen;

	if (!reply)
		return nil;
	list = [NSMutableArray array];
	seen = [NSMutableSet set];
	for (NSString *line in [reply componentsSeparatedByString:@"\n"]) {
		NSArray<NSString *> *f = [line componentsSeparatedByString:@"\t"];

		if (f.count < 8 || ![f[0] isEqualToString:@"bss"])
			continue;
		if ([f[1] isEqualToString:@"-"] || [seen containsObject:f[1]])
			continue;
		[seen addObject:f[1]];
		[list addObject:@{
			@"name" : f[1],
			@"channel" : @([f[3] intValue]),
			@"signal" : @([f[4] intValue]),
			@"usable" : @([f[5] intValue] != 0),
			@"security" : f[7],
		}];
	}
	return list;
}

static NSSet<NSString *> *KnownNetworks(void)
{
	NSMutableSet *known = [NSMutableSet set];

	for (NSString *line in [Ask(@"LIST") componentsSeparatedByString:@"\n"]) {
		NSArray<NSString *> *f = [line componentsSeparatedByString:@"\t"];

		if (f.count >= 2 && [f[0] isEqualToString:@"net"])
			[known addObject:f[1]];
	}
	return known;
}

// MARK: - barre de menus

@interface AppDelegate : NSObject <NSApplicationDelegate, NSMenuDelegate>
- (void)dumpMenu;
@end

@implementation AppDelegate {
	NSStatusItem *_item;
	NSMenu *_menu;
	NSDictionary *_status;
	NSArray<NSDictionary *> *_networks;
	NSSet<NSString *> *_known;
	BOOL _scanning;
	BOOL _menuIsOpen;
	NSTimer *_timer;
	dispatch_queue_t _work;
}

- (void)applicationDidFinishLaunching:(NSNotification *)note
{
	_work = dispatch_queue_create("xg760a.requetes", DISPATCH_QUEUE_SERIAL);
	_networks = @[];
	_known = [NSSet set];
	_menu = [[NSMenu alloc] init];
	_menu.delegate = self;
	_menu.autoenablesItems = NO;
	_item = [[NSStatusBar systemStatusBar]
		statusItemWithLength:NSVariableStatusItemLength];
	_item.menu = _menu;
	[self updateIcon];
	[self refreshStatus];
	_timer = [NSTimer scheduledTimerWithTimeInterval:4
						  target:self
						selector:@selector(refreshStatus)
						userInfo:nil
						 repeats:YES];
}

// l'icône dit en permanence si la clé est connectée
- (void)updateIcon
{
	NSStatusBarButton *button = _item.button;
	NSImage *image = nil;

	if (@available(macOS 11.0, *))
		image = [NSImage imageWithSystemSymbolName:
					 @"antenna.radiowaves.left.and.right"
				  accessibilityDescription:@"Wi-Fi XG-760A"];
	if (image) {
		image.template = YES;
		button.image = image;
		button.title = @"";
	} else {
		button.image = nil;
		button.title = @"XG";
	}
	button.appearsDisabled = !IsConnected(_status);
	button.toolTip = [@"Clé Wi-Fi Sagem XG-760A — "
		stringByAppendingString:Summary(_status)];
}

- (void)refreshStatus
{
	dispatch_async(_work, ^{
		NSDictionary *st = FetchStatus();

		dispatch_async(dispatch_get_main_queue(), ^{
			self->_status = st;
			[self updateIcon];
			if (self->_menuIsOpen)
				[self rebuildMenu];
		});
	});
}

- (void)startScan
{
	if (_scanning)
		return;
	_scanning = YES;
	dispatch_async(_work, ^{
		NSArray *list = ScanNetworks();
		NSSet *known = KnownNetworks();

		dispatch_async(dispatch_get_main_queue(), ^{
			self->_scanning = NO;
			if (list)
				self->_networks = list;
			self->_known = known;
			if (self->_menuIsOpen)
				[self rebuildMenu];
		});
	});
}

- (void)menuWillOpen:(NSMenu *)menu
{
	_menuIsOpen = YES;
	[self rebuildMenu];
	[self refreshStatus];
	if (_status && [_status[@"device"] length])
		[self startScan];
}

- (void)menuDidClose:(NSMenu *)menu
{
	_menuIsOpen = NO;
}

- (void)addInfo:(NSString *)title
{
	NSMenuItem *entry = [[NSMenuItem alloc] initWithTitle:title
						       action:NULL
						keyEquivalent:@""];

	entry.enabled = NO;
	[_menu addItem:entry];
}

- (void)rebuildMenu
{
	NSDictionary *st = _status;
	int state = [st[@"state"] intValue];
	NSMenuItem *entry;

	[_menu removeAllItems];
	[self addInfo:@"Clé Wi-Fi Sagem XG-760A"];
	[self addInfo:Summary(st)];
	if (IsConnected(st)) {
		NSString *ip = st[@"ipv4"];

		[self addInfo:ip.length ?
			[NSString stringWithFormat:@"Adresse %@ (%@)", ip,
						   st[@"iface"]] :
			@"Adresse IP en cours d'attribution…"];
	} else if ([st[@"error"] length]) {
		[self addInfo:st[@"error"]];
	}
	if (!st)
		[self addInfo:@"Réinstallez le pilote ou redémarrez le Mac."];

	if (st && [st[@"device"] length]) {
		NSString *current = state >= WLAN_AUTHENTICATING ? st[@"ssid"] : @"";

		[_menu addItem:[NSMenuItem separatorItem]];
		[self addInfo:_scanning ? @"Réseaux à portée — recherche…" :
					  @"Réseaux à portée"];
		for (NSDictionary *n in _networks) {
			NSString *name = n[@"name"];
			NSString *security = n[@"security"];
			BOOL usable = [n[@"usable"] boolValue];
			NSMutableString *title = [NSMutableString
				stringWithFormat:@"%@   %@",
						 Bars([n[@"signal"] intValue]),
						 SsidText(name)];

			if (![security isEqualToString:@"ouvert"])
				[title appendString:@"   🔒"];
			if (!usable)
				[title appendFormat:@"   (%@, non pris en charge)",
						    security];
			entry = [[NSMenuItem alloc]
				initWithTitle:title
				       action:@selector(chooseNetwork:)
				keyEquivalent:@""];
			entry.target = self;
			entry.representedObject = name;
			entry.enabled = usable;
			entry.state = ([name isEqualToString:current] &&
				       IsConnected(st)) ? NSControlStateValueOn :
							  NSControlStateValueOff;
			[_menu addItem:entry];
		}
		if (_networks.count == 0 && !_scanning)
			[self addInfo:@"Aucun réseau trouvé"];

		if (state >= WLAN_SCANNING &&
		    ![st[@"autoconnect"] isEqualToString:@"0"] &&
		    [st[@"known"] intValue] > 0) {
			[_menu addItem:[NSMenuItem separatorItem]];
			entry = [[NSMenuItem alloc]
				initWithTitle:@"Se déconnecter"
				       action:@selector(disconnect:)
				keyEquivalent:@""];
			entry.target = self;
			[_menu addItem:entry];
		}
	}
	[_menu addItem:[NSMenuItem separatorItem]];
	entry = [[NSMenuItem alloc] initWithTitle:@"Quitter"
					   action:@selector(quit:)
				    keyEquivalent:@"q"];
	entry.target = self;
	[_menu addItem:entry];
}

/// Mise au point : construit le menu comme à l'écran et l'écrit en texte.
- (void)dumpMenu
{
	_menu = [[NSMenu alloc] init];
	_status = FetchStatus();
	_networks = (_status && [_status[@"device"] length]) ?
		(ScanNetworks() ?: @[]) : @[];
	_known = KnownNetworks();
	_status = FetchStatus();
	[self rebuildMenu];
	for (NSMenuItem *entry in _menu.itemArray) {
		if (entry.isSeparatorItem)
			printf("  ----------\n");
		else
			printf("  %s %s%s\n",
			       entry.state == NSControlStateValueOn ? "✓" : " ",
			       entry.title.UTF8String,
			       entry.isEnabled ? "" : "   [inactif]");
	}
}

- (void)quit:(id)sender
{
	[NSApp terminate:nil];
}

- (void)disconnect:(id)sender
{
	dispatch_async(_work, ^{
		Ask(@"DISCONNECT");
		dispatch_async(dispatch_get_main_queue(), ^{
			[self refreshStatus];
		});
	});
}

- (NSString *)askPasswordFor:(NSString *)name
{
	NSAlert *alert = [[NSAlert alloc] init];
	NSSecureTextField *field = [[NSSecureTextField alloc]
		initWithFrame:NSMakeRect(0, 0, 280, 24)];

	alert.messageText = [NSString
		stringWithFormat:@"Mot de passe du réseau « %@ »", name];
	alert.informativeText =
		@"La clé Wi-Fi XG-760A a besoin du mot de passe WPA de ce réseau "
		@"(8 à 63 caractères). Il n'est pas conservé : seule la clé qui en "
		@"dérive est mémorisée par le pilote.";
	alert.accessoryView = field;
	[alert addButtonWithTitle:@"Se connecter"];
	[alert addButtonWithTitle:@"Annuler"];
	alert.window.initialFirstResponder = field;
	[NSApp activateIgnoringOtherApps:YES];
	if ([alert runModal] != NSAlertFirstButtonReturn)
		return nil;
	return field.stringValue;
}

- (void)show:(NSString *)title text:(NSString *)text
{
	NSAlert *alert = [[NSAlert alloc] init];

	alert.messageText = title;
	alert.informativeText = text;
	[NSApp activateIgnoringOtherApps:YES];
	[alert runModal];
}

- (void)chooseNetwork:(NSMenuItem *)sender
{
	NSString *name = sender.representedObject;
	NSString *text = SsidText(name);
	NSDictionary *network = nil;
	NSString *key;

	for (NSDictionary *n in _networks)
		if ([n[@"name"] isEqualToString:name])
			network = n;
	if (!network)
		return;

	if ([network[@"security"] isEqualToString:@"ouvert"]) {
		key = @"open";
	} else if ([_known containsObject:name]) {
		key = @"known";
	} else {
		NSString *pass = [self askPasswordFor:text];

		if (!pass)
			return;
		key = WpaKey(pass, name);
		if (!key) {
			[self show:@"Mot de passe invalide"
			      text:@"Un mot de passe WPA compte 8 à 63 caractères."];
			return;
		}
	}

	dispatch_async(_work, ^{
		NSString *reply = Ask([NSString
			stringWithFormat:@"CONNECT %@ %@", name, key]);
		NSString *outcome = @"Le pilote continue d'essayer en arrière-plan.";
		BOOL failed = YES;

		if (![reply hasPrefix:@"ok"]) {
			dispatch_async(dispatch_get_main_queue(), ^{
				[self show:@"Connexion impossible"
				      text:@"Le service du pilote n'a pas accepté la demande."];
			});
			return;
		}
		// suit la tentative une trentaine de secondes
		for (int step = 0; step < 60; step++) {
			NSDictionary *st;
			NSString *error;
			int state;

			usleep(500 * 1000);
			st = FetchStatus();
			dispatch_async(dispatch_get_main_queue(), ^{
				self->_status = st;
				[self updateIcon];
			});
			if (IsConnected(st)) {
				failed = NO;
				break;
			}
			error = st[@"error"] ?: @"";
			state = [st[@"state"] intValue];
			if (step >= 6 && state <= WLAN_SCANNING &&
			    [error containsString:@"mot de passe"]) {
				// ne pas mémoriser une clé que la box refuse
				Ask([@"FORGET " stringByAppendingString:name]);
				outcome = @"Le mot de passe a été refusé par le point "
					  @"d'accès. Choisissez de nouveau le réseau "
					  @"pour le ressaisir.";
				break;
			}
			if (step >= 6 && state <= WLAN_SCANNING &&
			    [error containsString:@"non prise en charge"]) {
				outcome = error;
				break;
			}
		}
		dispatch_async(dispatch_get_main_queue(), ^{
			[self refreshStatus];
			if (failed)
				[self show:[NSString stringWithFormat:
						@"Pas encore connecté à « %@ »", text]
				      text:outcome];
		});
	});
}

@end

int main(int argc, const char **argv)
{
	@autoreleasepool {
		// modes de vérification, sans interface graphique
		if (argc > 1 && !strcmp(argv[1], "--etat")) {
			NSDictionary *st = FetchStatus();

			printf("%s\n", Summary(st).UTF8String);
			if ([st[@"ipv4"] length])
				printf("Adresse %s (%s)\n", [st[@"ipv4"] UTF8String],
				       [st[@"iface"] UTF8String]);
			return st ? 0 : 1;
		}
		if (argc > 1 && !strcmp(argv[1], "--recherche")) {
			NSArray *list = ScanNetworks();

			if (!list) {
				printf("Service du pilote arrêté\n");
				return 1;
			}
			for (NSDictionary *n in list)
				printf("%s  %s  canal %d  %s%s\n",
				       Bars([n[@"signal"] intValue]).UTF8String,
				       SsidText(n[@"name"]).UTF8String,
				       [n[@"channel"] intValue],
				       [n[@"security"] UTF8String],
				       [n[@"usable"] boolValue] ? "" :
					       "  [non pris en charge]");
			return 0;
		}

		if (argc > 1 && !strcmp(argv[1], "--menu")) {
			[[[AppDelegate alloc] init] dumpMenu];
			return 0;
		}

		NSApplication *app = [NSApplication sharedApplication];
		AppDelegate *delegate = [[AppDelegate alloc] init];

		app.delegate = delegate;
		[app setActivationPolicy:NSApplicationActivationPolicyAccessory];
		[app run];
	}
	return 0;
}
