'use strict';
'require dom';
'require form';
'require fs';
'require poll';
'require rpc';
'require uci';
'require ui';
'require validation';
'require view';

const SERVICE = 'tg-ws-proxy-rs';
const BINARY = '/usr/bin/tg-ws-proxy-rs';
// The upstream tg-ws-proxy package runs under this service name and listens on
// 1443 by default, the same port as this one.
const UPSTREAM_SERVICE = 'tg-ws-proxy';
const isReadonlyView = !L.hasViewPermission() || null;

const callServiceList = rpc.declare({
	object: 'service',
	method: 'list',
	params: [ 'name' ],
	expect: { '': {} }
});

function runningInstance(services, name) {
	const instances = (services[name] || {}).instances || {};
	for (const id in instances) {
		if (instances[id].running)
			return { pid: instances[id].pid || null };
	}
	return null;
}

function configuredPort() {
	return uci.get(SERVICE, 'main', 'port') || '1443';
}

// procd only sees the process exit, so a port held by another program shows up
// as a bare STOPPED that the Start button cannot fix.
function portInUse(port) {
	return L.resolveDefault(fs.exec('/bin/netstat', ['-lnt']), null).then((result) =>
		!!result && String(result.stdout || '').split('\n').some((line) => {
			const fields = line.trim().split(/\s+/);
			const local = fields[3] || '';
			return /^tcp/.test(fields[0]) && local.slice(local.lastIndexOf(':') + 1) === port;
		}));
}

function serviceStatus() {
	return L.resolveDefault(callServiceList(SERVICE), {}).then((services) => {
		const instance = runningInstance(services, SERVICE);
		if (instance)
			return { running: true, pid: instance.pid };
		return portInUse(configuredPort()).then((portBusy) => {
			if (!portBusy)
				return { running: false };
			return L.resolveDefault(callServiceList(UPSTREAM_SERVICE), {}).then((upstream) => ({
				running: false,
				portBusy: true,
				upstream: runningInstance(upstream, UPSTREAM_SERVICE)
			}));
		});
	});
}

function statusNode(status) {
	const port = configuredPort();
	const state = status.running ? _('RUNNING') : _('STOPPED');
	const color = status.running ? 'green' : 'red';
	let detail;
	if (status.running && status.pid)
		detail = _('PID %s, listening on TCP %s').format(status.pid, port);
	else if (status.upstream)
		detail = _('TCP port %s is already in use, and the service of the separate tg-ws-proxy package is running (PID %s). Stop and disable it, or change the listen port.').format(port, status.upstream.pid || '?');
	else if (status.portBusy)
		detail = _('TCP port %s is already in use by another program. Stop it, or change the listen port.').format(port);
	else
		detail = _('Configured TCP port: %s').format(port);

	return E('span', {}, [
		E('strong', { style: 'color:%s'.format(color) }, state),
		' — ',
		detail
	]);
}

// Asked of the binary rather than of this package: the two are installed
// separately, so only the binary knows which release is actually running.
function binaryVersion() {
	return fs.exec(BINARY, ['--version']).then((result) => {
		const version = result.code === 0 && String(result.stdout || '').match(/\d+\.\d+\.\d+\S*/);
		return version
			? { version: version[0] }
			: { error: _('%s does not run on this router (exit code %s). Install the release archive built for this architecture.').format(BINARY, result.code) };
	}).catch((error) => ({
		error: error.name === 'NotFoundError'
			? _('%s is missing. Run install.sh, or save the tg-ws-proxy binary from the release archive under this name.').format(BINARY)
			: _('Version is not available: %s').format(error.message)
	}));
}

function binaryNode(binary) {
	return binary.version
		? _('Version: %s').format(binary.version)
		: E('span', { style: 'color:red' }, binary.error);
}

function formatLogLine(line) {
	const value = String(line || '');
	const traced = value.match(/^[A-Z][a-z]{2}\s+([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\d{4}\s+\S+\s+tg-ws-proxy-rs\[\d+\]:\s+\d{4}-\d{2}-\d{2}T\S+\s+(TRACE|DEBUG|INFO|WARN|ERROR)\s+(\S+):\s*(.*)$/);
	if (traced) {
		const level = traced[2];
		const target = traced[3];
		if ((level === 'TRACE' || level === 'DEBUG') &&
			!/^tg_ws_proxy(?:_rs)?(?:::|$)/.test(target))
			return null;
		return `${traced[1]} [${level}] ${target} — ${traced[4]}`;
	}

	const plain = value.match(/^[A-Z][a-z]{2}\s+([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\d{4}\s+\S+\s+tg-ws-proxy-rs\[\d+\]:\s*(.*)$/);
	return plain ? `${plain[1]} ${plain[2]}` : value;
}

function validateSecrets(sectionId, value) {
	if (!value)
		return true;
	const secrets = value.split(',');
	if (secrets.length > 0 && secrets.every((secret) => /^(?:[0-9a-fA-F]{2}){16,}$/.test(secret)))
		return true;
	return _('Expecting comma-separated even-length hexadecimal secrets of at least 32 characters each');
}

function validateDatatype(type, value, args) {
	const stub = {
		factory: validation,
		value,
		apply: function(innerType, innerValue, args) {
			if (innerValue != null)
				this.value = innerValue;
			return validation.types[innerType].apply(this, args || []);
		},
		assert: (condition) => !!condition
	};
	return validation.types[type].apply(stub, args || []) === true;
}

function validateDcIp(sectionId, value) {
	if (!value)
		return true;
	const match = value.match(/^([0-9]+):(.+)$/);
	if (!match || Number(match[1]) > 0xFFFFFFFF || !validateDatatype('ipaddr', match[2], [true]))
		return _('Expecting DC:IP with an unsigned 32-bit DC number and a valid IPv4/IPv6 address');
	return true;
}

function addValue(section, tab, option, title, description, datatype, placeholder, defaultValue) {
	const o = section.taboption(tab, form.Value, option, title, description);
	if (datatype)
		o.datatype = datatype;
	if (placeholder)
		o.placeholder = placeholder;
	if (defaultValue !== undefined)
		o.default = defaultValue;
	return o;
}

function addFlag(section, tab, option, title, description, defaultValue) {
	const o = section.taboption(tab, form.Flag, option, title, description);
	o.default = defaultValue || '0';
	o.rmempty = false;
	return o;
}

function addSeconds(section, option, title, description, defaultValue) {
	return addValue(section, 'timeouts', option, title, description, 'uinteger', null, defaultValue);
}

function isUnspecified(host) {
	return host === '0.0.0.0' || host === '::';
}

function isLoopback(host) {
	return /^127\./.test(host) || host === '::1';
}

// `--print-links` arguments for the saved settings: the binary builds the
// links, so their format lives only in each inbound's `links`.
function printLinksArgs() {
	const get = (option, fallback) => uci.get(SERVICE, 'main', option) || fallback;
	const host = get('host', '0.0.0.0');
	const args = [ '--print-links', '--host', host, '--port', get('port', '1443'),
		'--secret', get('secret', '') ];
	// A wildcard or loopback listener is advertised on the address LuCI was
	// opened on: on a router the binary's own guess is the uplink address,
	// which LAN devices are not meant to use.
	const linkIp = get('link_ip', '') ||
		((isUnspecified(host) || isLoopback(host)) ? window.location.hostname : '');
	if (linkIp)
		args.push('--link-ip', linkIp);
	const domain = get('listen_faketls_domain', '');
	if (domain)
		args.push('--listen-faketls-domain', domain);
	if (get('socks_enabled', '0') === '1')
		args.push('--socks-enabled', '--socks-host', get('socks_host', '127.0.0.1'),
			'--socks-port', get('socks_port', '1080'));
	return args;
}

const LINK_PURPOSES = {
	'Telegram': _('Telegram'),
	'Router service': _('Router service (Forkop, sing-box)')
};

// One `inbound<TAB>label<TAB>url` line per link; repeated labels are the
// per-user secrets of one inbound, numbered from the second.
function parseLinks(stdout) {
	const seen = {};
	return String(stdout || '').split('\n')
		.map((line) => line.split('\t'))
		.filter((fields) => fields.length === 3)
		.map(([ inbound, label, url ]) => {
			const key = inbound + '\t' + label;
			seen[key] = (seen[key] || 0) + 1;
			const purpose = LINK_PURPOSES[label] || label;
			return {
				inbound,
				purpose: seen[key] > 1 ? _('%s, secret %d').format(purpose, seen[key]) : purpose,
				url
			};
		});
}

function copyText(text) {
	if (navigator.clipboard && window.isSecureContext)
		return navigator.clipboard.writeText(text);
	// LuCI is usually plain HTTP, where the Clipboard API does not exist.
	const area = E('textarea', { readonly: '', style: 'position:fixed;top:-100px;opacity:0' }, text);
	document.body.appendChild(area);
	area.select();
	let copied = false;
	try {
		copied = document.execCommand('copy');
	} catch (error) {}
	area.remove();
	return copied ? Promise.resolve() : Promise.reject(new Error('clipboard unavailable'));
}

return view.extend({
	load() {
		return Promise.all([ uci.load(SERVICE), binaryVersion() ]);
	},

	updateStatus() {
		return serviceStatus().then((status) => {
			const node = document.getElementById('tg_ws_proxy_service_status');
			if (node)
				dom.content(node, statusNode(status));
		});
	},

	updateLog() {
		return fs.exec_direct('/sbin/logread', ['-e', SERVICE], 'text').then((text) => {
			const node = document.getElementById('tg_ws_proxy_live_log');
			if (!node)
				return;
			const lines = String(text || '').trimEnd().split('\n')
				.map(formatLogLine).filter((line) => line !== null);
			const visible = lines.slice(-500).join('\n').trim();
			node.textContent = visible || _('Log is empty.');
			node.scrollTop = node.scrollHeight;
		}).catch((error) => {
			const node = document.getElementById('tg_ws_proxy_live_log');
			if (node)
				node.textContent = _('Log is not available yet: %s').format(error.message);
		});
	},

	handleLogRefresh() {
		return this.updateLog();
	},

	renderLogWidget() {
		if (!this.logPollRegistered) {
			poll.add(() => this.updateLog());
			this.logPollRegistered = true;
		}
		window.setTimeout(() => this.updateLog(), 0);
		return E('div', { class: 'cbi-section' }, [
			E('div', { style: 'margin-bottom:0.5em' }, [
				E('button', {
					type: 'button',
					class: 'btn cbi-button cbi-button-action',
					click: ui.createHandlerFn(this, 'handleLogRefresh')
				}, _('Refresh')),
			]),
			E('pre', {
				id: 'tg_ws_proxy_live_log',
				wrap: 'pre',
				style: 'max-height:420px;overflow:auto;white-space:pre-wrap;word-break:break-word'
			}, _('Collecting data...')),
			E('div', { style: 'text-align:right' },
				E('small', {}, _('Shows the latest 500 matching lines from OpenWrt logd. Refresh every %s seconds.').format(L.env.pollinterval)))
		]);
	},

	handleCopy(url, event) {
		const button = event.currentTarget;
		return copyText(url).then(() => {
			button.textContent = _('Copied');
			window.setTimeout(() => { button.textContent = _('Copy'); }, 1500);
		}).catch(() => {
			// Still let the user copy it by hand.
			window.prompt(_('Copy the link:'), url);
		});
	},

	updateLinks() {
		const node = document.getElementById('tg_ws_proxy_links');
		if (!node)
			return Promise.resolve();
		if (!uci.get(SERVICE, 'main', 'secret')) {
			dom.content(node, E('em', {}, _('No proxy secret is set yet.')));
			return Promise.resolve();
		}
		return fs.exec(BINARY, printLinksArgs()).then((result) => {
			if (result.code !== 0)
				throw new Error((result.stderr || '').trim() || _('exit code %d').format(result.code));
			dom.content(node, this.linksTable(parseLinks(result.stdout)));
		}).catch((error) => {
			dom.content(node, E('em', {}, _('Links are unavailable: %s').format(error.message)));
		});
	},

	linksTable(links) {
		return E('table', { class: 'table' }, links.map((link) => E('tr', { class: 'tr' }, [
			E('td', { class: 'td left', style: 'white-space:nowrap' }, [
				E('strong', {}, link.inbound), E('br'), link.purpose
			]),
			// Masked like the secret field; the Copy button has the full link.
			E('td', { class: 'td left', style: 'word-break:break-all' },
				E('code', {}, link.url.replace(/(secret=)[^&]+/, '$1••••••••'))),
			E('td', { class: 'td right' }, E('button', {
				type: 'button',
				class: 'btn cbi-button cbi-button-action',
				click: ui.createHandlerFn(this, 'handleCopy', link.url)
			}, _('Copy')))
		])));
	},

	handleServiceAction(action, event) {
		const button = event.currentTarget;
		button.disabled = true;
		return fs.exec('/etc/init.d/tg-ws-proxy-rs', [action]).then((result) => {
			if (result.code !== 0)
				throw new Error(_('Command failed'));
			return new Promise((resolve) => window.setTimeout(resolve, 500));
		}).then(() => this.updateStatus()).catch((error) => {
			ui.addNotification(null, E('p', {},
				_('Unable to %s tg-ws-proxy-rs: %s').format(action, error.message)));
		}).finally(() => {
			button.disabled = isReadonlyView;
		});
	},

	render(data) {
		let m, s, o;
		const self = this;
		const binary = data[1];

		m = new form.Map('tg-ws-proxy-rs', _('Telegram WS Proxy (Rust)'),
			_('Telegram MTProto proxy with WebSocket, FakeTLS, Cloudflare and upstream proxy fallbacks.'));

		s = m.section(form.TypedSection);
		s.render = function() {
			if (!self.statusPollRegistered) {
				poll.add(() => self.updateStatus());
				self.statusPollRegistered = true;
			}
			return E('div', { class: 'cbi-section' }, [
				E('h3', {}, _('Service status')),
				E('p', { id: 'tg_ws_proxy_service_status' }, _('Collecting data...')),
				E('p', {}, binaryNode(binary)),
				E('div', {}, [
					E('button', {
						class: 'btn cbi-button cbi-button-positive',
						click: ui.createHandlerFn(self, 'handleServiceAction', 'start'),
						disabled: isReadonlyView
					}, _('Start')),
					' ',
					E('button', {
						class: 'btn cbi-button cbi-button-action',
						click: ui.createHandlerFn(self, 'handleServiceAction', 'restart'),
						disabled: isReadonlyView
					}, _('Restart')),
					' ',
					E('button', {
						class: 'btn cbi-button cbi-button-negative',
						click: ui.createHandlerFn(self, 'handleServiceAction', 'stop'),
						disabled: isReadonlyView
					}, _('Stop'))
				])
			]);
		};

		s = m.section(form.TypedSection);
		s.render = function() {
			window.setTimeout(() => self.updateLinks(), 0);
			return E('div', { class: 'cbi-section' }, [
				E('h3', {}, _('Connection links')),
				E('div', { id: 'tg_ws_proxy_links' }, _('Collecting data...')),
				E('div', {}, E('small', {}, _('Built from the saved settings; after changing them, Save & Apply.')))
			]);
		};

		s = m.section(form.NamedSection, 'main', 'tg-ws-proxy-rs', _('Settings'));
		s.addremove = false;
		s.tab('general', _('General'));
		s.tab('routing', _('Routing & fallbacks'));
		s.tab('performance', _('Performance'));
		s.tab('timeouts', _('Timeouts & cooldowns'));
		s.tab('logging', _('Logging & security'));

		o = addFlag(s, 'general', 'enabled', _('Enable service'),
			_('Start tg-ws-proxy-rs under procd and enable automatic respawn.'), '0');

		o = addValue(s, 'general', 'host', _('Listen address'), null,
			'ipaddr', '0.0.0.0', '0.0.0.0');
		o.rmempty = false;

		o = addValue(s, 'general', 'port', _('Listen port'), null,
			'port', '1443', '1443');
		o.rmempty = false;

		o = addFlag(s, 'general', 'socks_enabled', _('Enable SOCKS5 input'),
			_('Telegram TCP only. Shares the existing WebSocket and fallback settings. No SOCKS authentication.'), '0');
		o = addValue(s, 'general', 'socks_host', _('SOCKS5 listen address'),
			_('Keep 127.0.0.1 for Forkop on this router. A LAN address allows trusted devices to connect without a password.'),
			'ipaddr(1)', '127.0.0.1', '127.0.0.1');
		o.depends('socks_enabled', '1');
		o.retain = true;
		o.rmempty = false;
		o = addValue(s, 'general', 'socks_port', _('SOCKS5 listen port'), null,
			'port', '1080', '1080');
		o.depends('socks_enabled', '1');
		o.retain = true;
		o.rmempty = false;
		o = s.taboption('general', form.DynamicList, 'socks_dc', _('SOCKS5 destination DC mappings'),
			_('Optional signed DC:IP entries for client destinations missing from the built-in map; a negative DC marks a media address, e.g. -2:203.0.113.10 for DC2 media. These do not change upstream DC overrides.'));
		o.depends('socks_enabled', '1');
		o.retain = true;
		o.validate = function(sectionId, value) {
			if (!value) return true;
			const match = value.match(/^(-?(?:[1-5]|203)):(.+)$/);
			return (match && validateDatatype('ipaddr', match[2], [true]))
				? true : _('Expecting signed DC:IP (DC 1..5 or 203; negative for media)');
		};

		o = addValue(s, 'general', 'secret', _('Proxy secrets'),
			_('Comma-separated proxy secrets stored in UCI. Leave empty once to generate one persistent random secret at service start.'));
		o.password = true;
		o.validate = validateSecrets;

		o = addValue(s, 'general', 'link_ip', _('Public link host'),
			_('Hostname or IP advertised in the generated tg:// proxy link.'), 'host');
		o = addValue(s, 'general', 'listen_faketls_domain', _('Inbound FakeTLS domain'),
			_('Optional SNI hostname for inbound FakeTLS camouflage.'), 'hostname');

		o = s.taboption('routing', form.DynamicList, 'dc_ip', _('Telegram DC overrides'),
			_('One entry per line in DC:IP form, for example 2:149.154.167.220.'));
		o.validate = validateDcIp;

		o = s.taboption('routing', form.DynamicList, 'cf_domain', _('Cloudflare proxy domains'));
		o.datatype = 'hostname';
		o = s.taboption('routing', form.DynamicList, 'cf_worker_domain', _('Cloudflare Worker domains'));
		o.datatype = 'hostname';
		o = s.taboption('routing', form.DynamicList, 'mtproto_proxy', _('Upstream MTProto proxies'),
			_('HOST:PORT:SECRET entries. Secrets are stored in UCI.'));
		o.password = true;
		o.validate = function(sectionId, value) {
			if (!value || /^[^:]+:[0-9]+:[0-9a-fA-F]+$/.test(value))
				return true;
			return _('Expecting HOST:PORT:SECRET');
		};

		o = addValue(s, 'routing', 'outbound_proxy', _('Outbound proxy URL'),
			_('HTTP, SOCKS5 or SOCKS5H URL used for outbound connections.'), null,
			'socks5h://127.0.0.1:1080');
		o = addFlag(s, 'routing', 'no_outbound_proxy', _('Disable outbound proxy'),
			_('Ignore configured and environment proxy settings.'), '0');
		o = addValue(s, 'routing', 'no_proxy', _('NO_PROXY'),
			_('Comma-separated hosts, suffixes or CIDR ranges that bypass the outbound proxy.'));
		o = addFlag(s, 'routing', 'default_domains', _('Use default Cloudflare domains'), null, '0');
		o = addFlag(s, 'routing', 'cf_priority', _('Prefer Cloudflare routes'),
			_('Try Cloudflare Worker/proxy before direct Telegram WebSocket routes.'), '0');
		o = addFlag(s, 'routing', 'cf_balance', _('Balance Cloudflare domains'),
			_('Rotate the first attempted Cloudflare domain between connections.'), '0');
		o = addValue(s, 'routing', 'fronting_domain', _('Domain-fronting SNI'), null, 'hostname');

		o = addValue(s, 'performance', 'pool_size', _('WebSocket pool size'), null,
			'uinteger', '4', '4');
		o.rmempty = false;
		o = addValue(s, 'performance', 'pool_max_age', _('Pool maximum age'),
			_('Maximum age of a pooled connection in seconds.'), 'uinteger', '55', '55');
		o.rmempty = false;
		o = addValue(s, 'performance', 'buf_kb', _('Buffer size (KiB)'), null,
			'uinteger', '256', '256');
		o.rmempty = false;
		o = addValue(s, 'performance', 'max_connections', _('Maximum client connections'),
			_('Leave empty to derive the limit from the process file-descriptor budget.'), 'uinteger');

		o = addSeconds(s, 'ws_connect_timeout', _('WebSocket connect timeout'), null, '10');
		o = addSeconds(s, 'ws_fail_probe_timeout', _('WebSocket failure probe timeout'), null, '2');
		o = addSeconds(s, 'ws_fail_cooldown', _('WebSocket failure cooldown'), null, '30');
		o = addSeconds(s, 'ws_redirect_cooldown', _('WebSocket redirect cooldown'), null, '300');
		o = addSeconds(s, 'ip_fail_cooldown', _('IP failure cooldown'), null, '3600');
		o = addSeconds(s, 'handshake_timeout', _('Client handshake timeout'), null, '10');
		o = addSeconds(s, 'tcp_fallback_timeout', _('TCP fallback timeout'), null, '10');
		o = addSeconds(s, 'upstream_connect_timeout', _('Upstream proxy connect timeout'), null, '5');
		o = addSeconds(s, 'upstream_fail_cooldown', _('Upstream proxy failure cooldown'), null, '60');
		o = addSeconds(s, 'cf_connect_timeout', _('Cloudflare connect timeout'), null, '10');
		o = addSeconds(s, 'cf_fail_cooldown', _('Cloudflare failure cooldown'), null, '60');
		o = addSeconds(s, 'fronting_cooldown', _('Successful fronting cooldown'), null, '1800');
		o = addSeconds(s, 'fronting_fail_cooldown', _('Fronting failure cooldown'), null, '60');

		o = s.taboption('logging', form.ListValue, 'log_level', _('Log level'),
			_('Native Rust tracing level passed through RUST_LOG.'));
		o.value('off', _('Off'));
		o.value('error', _('Error'));
		o.value('warn', _('Warn'));
		o.value('info', _('Info'));
		o.value('debug', _('Debug'));
		o.value('trace', _('Trace'));
		o.default = 'info';
		o.rmempty = false;
		o = s.taboption('logging', form.DummyValue, '_live_log', _('Live log'));
		o.renderWidget = function() {
			return self.renderLogWidget();
		};
		o = addFlag(s, 'logging', 'danger_accept_invalid_certs',
			_('Accept invalid TLS certificates'),
			_('Dangerous: disables certificate verification for Telegram/Cloudflare connections.'), '0');

		return m.render();
	}
});
