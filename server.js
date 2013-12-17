var httpProxy = require('http-proxy');
var fs = require('fs');
var http = require('http');
var https = require('https');
var crypto = require('crypto');
var path = require('path');
var childProcess = require('child_process');

var log4js = require('log4js');
log4js.loadAppender('file');
log4js.addAppender(log4js.appenders.file('service.log'), 'service');
var log = log4js.getLogger('service');

log.info('Hostname Dispatcher started.');

fs.watchFile('./hosts.json', readHosts);
readHosts();

var httpProxies = {};
var httpsProxies = {};

var defaultProxy = new httpProxy.HttpProxy({
	target: {
		host: 'localhost',
		port: 81
	}
});

function createCert(domain, callback) {
	childProcess.exec('openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -subj "/C=RO/L=Bucuresti/O=Zitec Com/OU=IT/CN=' +
					  domain + '" -keyout ' + getCertPath(domain, 'key') + ' -out ' + getCertPath(domain, 'crt'), function(error) {
		if (error) {
			return callback(error);
		}
		if (!certExists(domain)) {
			return callback(new Error('Could not generate certificate for domain ' + domain));
		}
		log.info('Created certificate for domain ' + domain);
		callback();
	});
}

function installCert(domain, callback) {
	childProcess.exec('certutil -addstore Root ' + getCertPath(domain, 'crt'), function(error, stdout) {
		if (error) {
			return callback(error);
		}
		if (stdout.indexOf('-addstore command completed successfully') < 0) {
			return callback(new Error('Could not install certificate for domain ' + domain));
		}
		log.info('Installed certificate for domain ' + domain);
		callback();
	});
}

RegExp.escape= function(s) {
    return s.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&');
};

function getCertPath(domain, type) {
	return path.join(__dirname, 'certs', domain + '.' + type);
}

function getCert(domain, type) {
	return fs.readFileSync(getCertPath(domain, type), 'utf-8');
}

function getCretentialsContext(domain) {
	return crypto.createCredentials({
		key: getCert(domain, 'key'),
		cert: getCert(domain, 'crt')
	}).context;
}

function certExists(domain) {
	return (fs.existsSync(getCertPath(domain, 'key'))
		&& fs.existsSync(getCertPath(domain, 'crt')));
}

function readHosts() {
	var windowsHostsFile = 'C:/Windows/System32/Drivers/etc/hosts';
	fs.readFile(windowsHostsFile, function(err, data) {
		if (err) {
			return log.warn('Could not load windows hosts file.');
		}
		
		var windowsHosts = data.toString();
		var shouldSave = false;
		
		var addHostname = function(hostname) {
			if (!(new RegExp('^.+\\s+' + RegExp.escape(hostname) + '$', 'mi')).test(windowsHosts)) {
				windowsHosts += '\n127.0.0.1\t\t\t' + hostname;
				log.info('Added ' + hostname + ' to windows hosts file.');
				shouldSave = true;
			}
		};
		
		fs.readFile('./hosts.json', function(err, data) {
			if (err) {
				return log.warn('Could not load hosts file.');
			}
			
			var hosts;
			try {
				hosts = JSON.parse(data);
			} catch (e) {
				return log.warn('Could not parse hosts file.');
			}
			
			httpProxies = {};
			httpsProxies = {};
			
			for (var alias in hosts) {
				addHostname(alias);
				
				var host = hosts[alias];
				var name = host.name || 'localhost';
				var sname = host.sname || name;
				
				if (host.port) {
					httpProxies[alias] = new httpProxy.HttpProxy({
						target: {
							host: name,
							port: host.port
						}
					});
				}
				
				if (host.sport) {
					httpsProxies[alias] = new httpProxy.HttpProxy({
						target: {
							host: sname,
							port: host.sport,
							https: true,
							rejectUnauthorized: false
						}
					});
					
					if (certExists(alias)) {
						httpsProxies[alias].SecureContext = getCretentialsContext(alias);
					} else {
						(function(domain) {
							createCert(domain, function(err) {
								if (err) {
									return log.error(err);
								}
								installCert(domain, function(err) {
									if (err) {
										return log.error(err);
									}
									httpsProxies[domain].SecureContext = getCretentialsContext(domain);
								});
							});
						})(alias);
					}
				}
			}
			
			log.info('Loaded ' + (Object.keys(httpProxies).length + Object.keys(httpsProxies).length) + ' routes.');
			
			if (shouldSave) {
				fs.writeFile(windowsHostsFile, windowsHosts, function(err) {
					if (err) {
						return log.warn('Could not save windows hosts file.');
					}
				});
			}
		});
	});
}

http.createServer(function(req, res) {
	var proxy = httpProxies[req.headers.host] || defaultProxy;
	proxy.proxyRequest(req, res);
}).listen(80);

var wildcardSecureContext = getCretentialsContext('wildcard');

https.createServer({
	SNICallback: function(domain) {
		if (!httpsProxies[domain] || !httpsProxies[domain].SecureContext) {
			return wildcardSecureContext;
		}
		return httpsProxies[domain].SecureContext;
	},
	key: getCert('wildcard', 'key'),
	cert: getCert('wildcard', 'crt')
}, function(req, res) {
	var proxy = httpsProxies[req.headers.host] || defaultProxy;
	proxy.proxyRequest(req, res);
}).listen(443);

http.createServer(function(req, res) {
	res.writeHead(404, {'Content-Type': 'text/html'});
	res.write('<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN"><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested hostname was not found in routing table on this server.</p><hr><address>HostnameDispatcher/1.0 Server at ' + req.headers.host + ' Port 80</address></body></html>');
	res.end();
}).listen(81);