var assert = require('simple-assert');
var fs = require('fs');

function loadModule(ctx) {
	var m = require(__dirname + "/../index");
	return m(ctx);
}

function fakeRequest(ip) {
	return {
		'ip': ip
	};
}

function fakeResponse() {
	return {
		'statusCode': 200,
		'buffer': null,
		'status': function(st) { this.statusCode = st; return this; },
		'send': function(buf) { this.buffer = buf; return this; }
	};
}

describe("Basic middleware test - IP table", () => {
	const TEST_DEV_IP = '127.0.0.1';
	const TEST_VIS_IP = '8.8.4.4';
	
	var restrict;
	
	it("Ensure it loads (source syntax sane)", () => {
		restrict = loadModule(['127.0.0.1']);
		assert(restrict);
	});

	it("Ensure it will permit developers from those IPs", () => {
		var req = fakeRequest(TEST_DEV_IP);
		var res = fakeResponse();
		
		var next_called = false;
		restrict(req, res, function() { next_called = true; });
		assert(res.statusCode == 200, "Response status was HTTP " + res.statusCode + ", not 200.");
		assert(next_called);
		
	});
	
	it("Ensure it will turn away unwelcome visitors from any other IPs with a 403", () => {
		var req = fakeRequest(TEST_VIS_IP);
		var res = fakeResponse();
		
		var next_called = false;
		restrict(req, res, function() { next_called = true; });
		assert(res.statusCode == 403, "Reponse status was HTTP " + res.statusCode + ", not 403.");
		assert.not(next_called);		
	});
});

describe("Basic middleware test - External JSON", () => {

	const fn = '/var/tmp/express-devel-restrict-whitelist.json';	
	const TEST_DEV_IP = '127.10.0.1';
	const TEST_DEV_IP_2 = '127.0.0.1';
	const TEST_VIS_IP = '8.8.4.4';
	
	var restrict;
	
	it("Ensure our file is ready", () => {
		var ips = [TEST_DEV_IP, TEST_DEV_IP_2];
		fs.writeFileSync(fn, JSON.stringify(ips));
		
		assert(fs.existsSync(fn));
	});
	
	it("Ensure it loads", () => {
		restrict = loadModule(fn);
		assert(restrict);
	});
	
	it("Ensure it will permit developers from those IPs", () => {
		var reqs = [ fakeRequest(TEST_DEV_IP), fakeRequest(TEST_DEV_IP_2) ];
		
		for (var ri in reqs) {
			var req = reqs[ri];
			var next_called = false;
			var res = fakeResponse();

			restrict(req, res, function() { next_called = true; });
			
			assert(res.statusCode == 200, "Response status was HTTP " + res.statusCode + ", not 200.");
			assert(next_called);
		}
	});
	
	it("Ensure it will turn away unwelcome visitors from any other IPs with a 403", () => {
		var req = fakeRequest(TEST_VIS_IP);
		var res = fakeResponse();
		
		var next_called = false;
		restrict(req, res, function() { next_called = true; });
		assert(res.statusCode == 403, "Reponse status was HTTP " + res.statusCode + ", not 403.");
		assert.not(next_called);		
	});
	
	it("Cleaning up", () => {
		fs.unlinkSync(fn);
	})
});

describe("Basic middleware test - Callback function", () => {

	var cb = function(ip) {
		if (! ip) return false;
		return ip.match(/^127\./) ? true : false; 	
	};
	
	const TEST_DEV_IP = '127.10.0.1';
	const TEST_VIS_IP = '8.8.4.4';
	
	var restrict;
	
	it("Ensure it loads", () => {
		restrict = loadModule(cb);
		assert(restrict);
	});

	it("Ensure it will permit developers from those IPs", () => {
		var req = fakeRequest(TEST_DEV_IP);
		var res = fakeResponse();
		
		var next_called = false;
		restrict(req, res, function() { next_called = true; });
		assert(res.statusCode == 200, "Response status was HTTP " + res.statusCode + ", not 200.");
		assert(next_called);
		
	});
	
	it("Ensure it will turn away unwelcome visitors from any other IPs with a 403", () => {
		var req = fakeRequest(TEST_VIS_IP);
		var res = fakeResponse();
		
		var next_called = false;
		restrict(req, res, function() { next_called = true; });
		assert(res.statusCode == 403, "Reponse status was HTTP " + res.statusCode + ", not 403.");
		assert.not(next_called);		
	});
});