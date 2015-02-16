
var util = exports

var brand = require("brorand")

util.HMAC   = require("./util/hmac.js").HMAC
util.PBKDF2 = require("./util/pbkdf.js").PBKDF2
util.AES    = require("./util/aes.js").AES

util.utf8String = require("./util/util.js").utf8String

util.isNumber = function isNumber(n) {
  // See http://stackoverflow.com/questions/18082/validate-decimal-numbers-in-javascript-isnumeric
  return !isNaN(parseFloat(n)) && isFinite(n);
};

util.isString = function isString(s) {
  return typeof s === 'string' || s.constructor === String /* same as 's instanceof String' */;
};

util.isArray = function isArray(a) {
  return a.constructor === Array /* same as 'a instanceof Array' */;
};


// 
// Logging facilities
// 

function logger() {
  // Logging levels
  logger.TRACE   = 2;
  logger.VERBOSE = 1;
  logger.NONE    = 0;

  this.level = logger.NONE;
};

logger.prototype._log = function _log(level, args) {
  if (level <= this.LEVEL) {
    console.log.apply(null, Array.prototype.concat.call([ "LOG[#" + level + "] " ], Array.prototype.slice.call(arguments, 1)));
  }
};

logger.prototype.v = function v(args) {
  return this._log.apply(this, Array.prototype.concat.call([ logger.VERBOSE ], arguments));
};

logger.prototype.t = function v(args) {
  return this._log.apply(this, Array.prototype.concat.call([ logger.TRACE ], arguments));
};

logger.prototype.set = function set(level) {
  this.LEVEL = level;
};

util.logger = logger;

//
// Marshalling harness
//

util.marshalNum = function marshalNum(n) {
  var bs = new Array();
  for (var i = 0; n !== 0; ++i) {
    bs.push(n & 0xFF);
    n = n >>> 8;
  }
  return bs;
}

util.marshalString = function marshalString(s) {
  var bs = new Array();
  for (var i = 0; i < s.length; ++i) {
    bs.push(s.charCodeAt(i));
  }
  return bs;
}

util.marshalArray = function marshalArray(a) {
  var bs = new Array();
  for (var i = 0; i < a.length; ++i) {
    Array.prototype.push.apply(bs, util.toBytes(a[i]))
  }
  return bs;
}

util.toBytes = function toBytes(x) {
  if (util.isNumber(x)) 
    return util.marshalNum(x); 
  else if (util.isString(x))
    return util.marshalString(x);
  else if (util.isArray(x))
    return util.marshalArray(x);
  else
    assert(false && "May not serialize something other than strings/numbers");
};


//
// Un-marshalling harness
//

util.unmarshalNum = function unmarshalNum(bs) {
  var n = 0;
  for (var i = bs.length - 1; i >= 0; --i) {
    n = (n << 8) + bs[i];
  }
  return n;
};

util.unmarshalString = function unmarshalString(bs) {
  var s = new String;
  for (var i = 0; i < bs.length; ++i) {
    s = s.concat(String.fromCharCode(bs[i]));
  }
  return s;
}

util.unmarshalInt32Array = function unmarshalint32array(bs) {
  var is = new Array;
  for (var i = 0; i < bs.length; i += 4) {
    is.push(util.unmarshalNum(bs.slice(i, i + 4)));
  }
  return is;
}


//
// Storage 
//

util.emplace = function toBytes(dst, ds, src, ss, len) {
  // TODO(kudinkin): ?
  len = Math.min(src.length, len);
  for (var i = 0; i < len; ++i) {
    dst[ds + i] = src[ss + i];
  }
};


//
// Exceptions
//

util.interrupt = function interrupt(m) {
  throw new Error('Interrupted! ' + m);
}


//
// Utilities
// 

util.randomBytes = function randomBytes(l) {
  return brand(l);
}
 

//
// Extensions
// 

Array.prototype.toUint8 = function Array$toUint8() {
  if (this.constructor === Uint8Array)
    return this;
  
  var ui8 = new Uint8Array(this.length);
  for (var i = 0; i < this.length; ++i)
    ui8[i] = this[i];

  return ui8;
};

Uint8Array.prototype.join = function Uint8Array$join(a) {
  var r = new Uint8Array(this.length + a.length);

  r.set(this, 0);
  r.set(a,    this.length);
  
  return r;
};

// TODO(kudinkin): Replace with proper extend
Object.prototype.extend = function (o) {
  for (var p in o)
    this[p] = o[p];
}

// TODO(kudinkin): Move out?
String.prototype.zfill = function zfill(len) {
  len = len - this.length;
  
  if (len <= 0)
    return this;

  var a = new Array(len);
  var i = len;

  while (i--)
    a[i] = '0';

  return a.join('').concat(this);
};

Uint8Array.prototype.inspect = function inspect() {
  var s = "[ ";
  for (var i = 0; i < this.length; ++i) {
    if (i != 0)
      s = s.concat(", ");
    s = s.concat(this[i]);
  }
  s = s.concat(" ]");
  return s; 
}

