var fs = require('fs');
var cout = require('debug')('DEVELRESTRICT');

function ExpressDevelRestrict(in_ctx) {
	this.permitted = null;
	this._buildWhiteList(in_ctx);
}

ExpressDevelRestrict.prototype.permit = function(ip) {
	if (process.env.NODE_ENV != 'development') {
		// unless we are for-sure running in dev mode
		// permit everything.
		cout("NO whitelist -- permitting all.");
		return true;
	}
	
	if (typeof this.permitted == 'function') {
		var rv = this.permitted(ip) ? true : false;
		cout("CB whitelist result -> " + (rv ? "Y" : "N"));
		return rv;
	} else if (this.permitted === null) 
		return false;		// no one is allowed in.
	else {
		var rv = this.permitted[ip] == true;
		cout(`${ip} is ` + (rv ? "ON" : "NOT ON") + " whitelist.");
		return rv;
	}
};

ExpressDevelRestrict.prototype.forbid = function(ip) {
	return !this.permit(ip);
};

ExpressDevelRestrict.prototype.go = function(req, res, next) {
	if (this.forbid(req.ip)) {
		res.status(403).send("Forbidden");
	} else {
		next();
	}
};

ExpressDevelRestrict.prototype._buildWhiteList = function(ctx) {
	if (ctx == null) return;
	
	if (typeof ctx == 'function') {
		// eval on demand.
		this.permitted = ctx;
	} else if (typeof ctx == 'object') {
		// list of IPs
		this.permitted = {};
		for (var i in ctx) {
			cout(`Adding ${ctx[i]} to whitelist.`);
			this.permitted[ctx[i]] = true;
		}
	} else if (typeof ctx == 'string') {
		// external file w/ IP list as JSON [ 'x.x.x.x', ... ];
		try {
			var ips = JSON.parse(fs.readFileSync(ctx));
			
			if (ips && typeof ips == 'object') {
				this._buildWhiteList(ips);
			}
		} catch (e) {
			console.error(`Failed to find/parse ${ctx} for your IP whitelist.`);	
			console.error(e.message);
		}
	}
};




module.exports = function(ctx) {
	var scope = new ExpressDevelRestrict(ctx);
	
	return ExpressDevelRestrict.prototype.go.bind(scope);
}

//if (! ExpressDevelRestrict.permit(req.ip)) {
//	res.setStatus(403).send("Forbidden");
//} else {
//	next();
//}		
