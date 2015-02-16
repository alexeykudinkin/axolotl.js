
var axolotl = exports; 

var assert = require("assert")

var ecc   = require("elliptic")
var hash  = require("hash.js")
var bn    = require("bn.js")

var util  = require("./util.js")

var djb = new ecc.ec("curve25519");

var AES     = util.AES;
var HMAC    = util.HMAC;
var PBKDF2  = util.PBKDF2;

// Enable logger
var log = new util.logger;


function Axolotl(mode) {
  var self = this;

  // TODO(kudinkin): Do we need this?
  if (mode === 'alice' || mode === 'bob')
    self.mode = mode;
  else
    throw new "Eve's has been caught!"; // TODO(kudinkin): Exception class?

  // TODO(kudinkin): Preserve stability during debug 
  //self.state = {
  //  DHI:  self.generateKeyPair(), /* Identity KP */
  //  DHHS: self.generateKeyPair(), /* Handshake KP */
  //  DHR:  self.generateKeyPair(), /* Ratcheting KP */
  //}
  if (self.mode === 'alice') {
    self.state = {
      DHI:  djb.keyFromPrivate("036be82be5e3f8e49390062c3c1ed92b76b83dfab6e1c228f3fd79f8ee8136b8", 16),
      DHHS: djb.keyFromPrivate("04a5c651202d7193c5089fb8b3336368f00bb6ae4c8df5f7eabe11b61a4f9cdd", 16),
      DHR:  djb.keyFromPrivate("027ecf5d60bd50d472ced827445772b37c739c6bdf2b33eed5cf28702f7610fd", 16) 
    };
  } else {
    self.state = {
      DHI:  djb.keyFromPrivate("0f49b0afabb388e30c6d2f5a3c937f05f3568eb3223aa328bc880421e4c71c77", 16),
      DHHS: djb.keyFromPrivate("03a01653b472beb112ca05356c9d2e300d0a724269c057690290efba1cfd0cd9", 16),
      DHR:  djb.keyFromPrivate("08e713c55d1f22289a2533e296a8fd42ea4fb6d2370c6d28cd05b20602e6162d", 16) 
    };
  }
}

axolotl.proto = Axolotl;

Axolotl.prototype.introduce = function introduce() {
  var self = this;
  return {
    identity: {
      PK: self.state.DHI.getPublic()
    },

    handshake: {
      PK: self.state.DHHS.getPublic()
    },

    ratchet: {
      PK: self.state.DHR.getPublic(), 
    }
  }
}

Axolotl.prototype.init = function init(other, verify) {
  if (verify) {
    assert(false && "Verifty other party identity!");
  }

  var self = this;

  // TODO(kudinkin): Tidy up
  assert(other.identity   && other.identity.PK);
  assert(other.handshake  && other.handshake.PK);
  assert(other.ratchet    && other.ratchet.PK);

  // TODO(kudinkin): Shim this?
  if (self.state.DHI.getPublic().getX() < other.identity.PK.getX())
    self.mode = 'alice';
  else
    self.mode = 'bob'; 

  self.state.DHIr = other.identity.PK;
  
  master_key = self.tripleDH(self.state.DHI, self.state.DHHS, other.identity.PK, other.handshake.PK);

  if (self.mode === 'alice') {
    self.state.extend({
      // Root key
      RK: self.PBKDF2(master_key, "0xDEADBEEF"),

      // Header keys
      HKs: self.PBKDF2(master_key, "0xDEADBABE"),
      HKr: self.PBKDF2(master_key, "0xBABEBEEF"),

      // Next-header keys
      NHKs: self.PBKDF2(master_key, "0xDEADC0DE"),
      NHKr: self.PBKDF2(master_key, "0xDEADDEAD"),
    
      // Chain keys
      CKs: self.PBKDF2(master_key, "0xDEADD00D"),
      CKr: self.PBKDF2(master_key, "0xDEAD10CC"),

      // Ratchet keys
      DHRs: {},
      DHRr: other.ratchet.PK,

      // Counters
      Ns:   0,
      Nr:   0,
      PNs:  0,

      // Ratchet flag
      RF: true
    });
  } else if (self.mode === 'bob') { 

    self.state.extend({
      // Root key
      RK: self.PBKDF2(master_key, "0xDEADBEEF"),

      // Header keys
      HKs: self.PBKDF2(master_key, "0xBABEBEEF"),
      HKr: self.PBKDF2(master_key, "0xDEADBABE"),

      // Next-header keys
      NHKs: self.PBKDF2(master_key, "0xDEADDEAD"),
      NHKr: self.PBKDF2(master_key, "0xDEADC0DE"),

      // Chain keys
      CKs: self.PBKDF2(master_key, "0xDEAD10CC"),
      CKr: self.PBKDF2(master_key, "0xDEADD00D"),

      // Ratchet keys
      DHRs: self.state.DHR,
      DHRr: {},

      // Counters
      Ns:   0,
      Nr:   0,
      PNs:  0,

      // Ratchet flag
      RF: false 
    });

  } else {
    assert(false && "Eve has been caught right away!")
  }

  // Storage (non-persistent) for the skipped message-/header-keys
  self.state.staged = new Array(); 
}

Axolotl.prototype._deriveRatchetKey = function deriveRatchetKey(r) {
  return r ? r.getPublic().getX().toString(16) : "";
}

Axolotl.prototype.encrypt = function encrypt(plaintext) {
    return this.encryptMessage(util.utf8String.toBits(plaintext));
}

Axolotl.prototype.encryptMessage = function encryptMessage(payload) {
  var self = this;

  // _DBG
  log.v(">> [x] ENCRYPT: BEGIN >>>>>>>>>>>>>>>");

  var ratcheting = false;

  // Ratchet
  if (self.state.RF) {
    // _DBG
    log.t(">> [x] RATCHET: BEGIN");

    ratcheting = true;

    self.state.DHRs = self.generateKeyPair();

    self.state.PNs  = self.state.Ns;
    self.state.Ns   = 0;

    self.state.HKs = self.state.NHKs;

    // _DBG
    log.t(">> [x] ROOT KEY PBKDF: BEGIN");

    // _DBG
    log.t("RK -BEFORE:", self.state.RK);
    log.t("DH",          self.DH(self.state.DHRs, self.state.DHRr).toString(16));
    log.t("HMAC",        self.HMAC(self.state.RK, self.DH(self.state.DHRs, self.state.DHRr).toString(16)));

    self.state.RK = self.PBKDF2(self.HMAC(self.state.RK, self.DH(self.state.DHRs, self.state.DHRr).toString(16)), "0xDEADBEEF");

    // _DBG
    log.t("RK -AFTER:", self.state.RK);

    // _DBG
    log.t(">> [x] ROOT KEY PBKDF: END");

    if (self.mode === 'alice') {

      self.state.NHKs = self.PBKDF2(self.state.RK, "0xDEADC0DE")
      self.state.CKs  = self.PBKDF2(self.state.RK, "0xDEADD00D")

    } else if (self.mode === 'bob') {

      self.state.NHKs = self.PBKDF2(self.state.RK, "0xDEADDEAD")
      self.state.CKs  = self.PBKDF2(self.state.RK, "0xDEAD10CC")

    }

    self.state.RF = false;
  }

  // _DBG
  log.t(">> [x] RATCHET: END");

  var header_key  = self.state.HKs;
  var message_key = self.HMAC(self.state.CKs, "0");

    // TODO(kudinkin): Extract
  var HEADER_LENGTH = 106;

  var header = new Uint8Array(HEADER_LENGTH);

  util.emplace(header, 0, util.toBytes(self.state.Ns),  0, 3);
  util.emplace(header, 3, util.toBytes(self.state.PNs), 0, 3);

  var header_len = 6; 

  if (ratcheting) {
    var ratchet_key = this._deriveRatchetKey(self.state.DHRs);

    // _DBG
    log.t(">> [x] RATCHET_KEY: ", ratchet_key);

    util.emplace(header, 6, util.toBytes(ratchet_key),    0, 100);

    header_len += ratchet_key.length;
  }

  // _DBG
  log.t(">> [x] RANDOM_STRING");
 
  var encrypted = {
    header: header,
    body:   util.toBytes(self._encrypt(payload, message_key)).toUint8(),
    seal:   function() {
              return this.header.join(this.body);
            }
  };

  var pad_len = HEADER_LENGTH - header_len;
  var pad     = util.randomBytes(pad_len - 1);

  // Pad header to have `HEADER_LENGTH` long
  util.emplace(header, header_len,  pad,                    0, 100);
  util.emplace(header, 105,         util.toBytes(pad_len),  0, 1);

  // _DBG
  //log.t(" HEADER: ",   encrypted.header);
  log.t(" BODY: ",     encrypted.body);
  log.t(" PADDING: ",  pad_len);

  self.state.Ns += 1;
  self.state.CKs = self.HMAC(self.state.CKs, "1");

  var bytes = encrypted.seal();

  // _DBG
  log.v(">> MODE[ " + self.mode + " ], RF[ " + self.state.RF + " ]");

  // _DBG
  log.v(">> [x] ENCRYPT: END >>>>>>>>>>>>>>>");

  return bytes;
}

Axolotl.prototype._encrypt = function _encrypt(bytes, key) {
  // TODO(kudinkin): Padding!
  var c = new AES(key)

  var out = [];
  var pad = [];

  if (bytes.length % 4 !== 0) {
    for (var i = 0; i < 4 - (bytes.length % 4); i++)
      pad.push(0);
  }

  var i = 0;
  for (; i < (bytes.length + pad.length - 4); i += 4)
    Array.prototype.push.apply(out, c.encrypt(bytes.slice(i, i + 4)));

  Array.prototype.push.apply(out, c.encrypt(bytes.slice(i).concat(pad)));

  return out;
}

Axolotl.prototype._unmarshalRatchetKey = function unmarshalRatchetKey(xs) {
  return djb.curve.point(xs, "1");
}

Axolotl.prototype.decrypt = function decrypt(bytes) {
  return util.utf8String.fromBits(this.decryptMessage(bytes));
}

Axolotl.prototype.decryptMessage = function decryptMessage(bytes) {
  var self = this;

  // _DBG
  log.v(">> [x] DECRYPT: BEGIN >>>>>>>>>>>>>>>");

  var padding = bytes.slice(105, 106)[0]; // < 106 

  // _DBG
  log.t(">> [x] PADDING: ", padding);

  var header  = bytes.slice(0, 106 - padding);
  var body    = bytes.slice(106);

  // Probe already seen message-keys
  var decrypted = {}; //self.probeSkippedKeys(bytes, padding);

  if (decrypted.body && decrypted.header)
    return decrypted.body;

  // Probe current header-key 
  decrypted.header = header; //self._decrypt(header, self.state.HKr);

  var DHRp; // Purported DHR
  var Np;   // Purported message number

  Np = util.unmarshalNum(header.slice(0, 3));

  if (header.length === 6)  DHRp = null;
  else                      DHRp = this._unmarshalRatchetKey(util.unmarshalString(decrypted.header.slice(6)));

  // _DBG
  log.t(" >> [x] PURPORTED RATCHET KEY: ", DHRp);

  // Check whether any ratcheting session is in progress
  if (!DHRp) {

    // Preserve missing message-keys for messages arriving out-of-order,
    // and derive keys for the current message 
    var next = self.stageSkippedKeys(Np, self.state.Nr, self.state.HKr, self.state.CKr);

    // TODO(kudinkin): Coherent marshalling?
    body = util.unmarshalInt32Array(body);

    decrypted.body = self._decrypt(body, next.MK);

    if (!decrypted.body)
      throw "Undecipherable!";

    self.state.CKr = next.CK;

  } else {

    // Probe next header-key 
    //decrypted.header = self._decrypt(header, self.state.NHKr);

    if (self.state.RF) {
      util.interrupt("Other ratcheting-session is in-progress! [" + self.mode + "]");
    }

    if (!decrypted.header)
      throw "Undecipherable!";

    // Next header-key involvement designates other-party having completed 
    // the ratchet round

    var PNp; // Purported previous message number

    PNp = util.unmarshalNum(decrypted.header.slice(3, 6));

    // _DBG
    log.t(">> Np: ",  Np);
    log.t(">> PNp: ", PNp);

    // Stage already skipped message keys
    self.stageSkippedKeys(PNp, self.state.Nr, self.state.HKr, self.state.CKr);

    // _DBG
    log.t(">> [x] RATCHET: BEGIN");
    log.t(">> [x] ROOT KEY PBKDF: BEGIN");

    // _DBG
    log.t("RK -BEFORE:",   self.state.RK);
    log.t("DH",            self.DH(self.state.DHRs, DHRp).toString(16));
    log.t("HMAC",          self.HMAC(self.state.RK, self.DH(self.state.DHRs, DHRp).toString(16)));

    var RKp = self.PBKDF2(self.HMAC(self.state.RK, self.DH(self.state.DHRs, DHRp).toString(16)), "0xDEADBEEF");

    // _DBG
    log.t("RK -AFTER:", RKp);
    log.t(">> [x] ROOT KEY PBKDF: END");
    log.t(">> [x] RATCHET: END");


    var HKp = self.state.NHKr;
    var CKp;

    if (self.mode === 'alice') {

      NHKp = self.PBKDF2(RKp, "0xDEADDEAD");
      CKp  = self.PBKDF2(RKp, "0xDEAD10CC")

    } else if (self.mode === 'bob') {

      NHKp = self.PBKDF2(RKp, "0xDEADC0DE");
      CKp  = self.PBKDF2(RKp, "0xDEADD00D")

    } else {
      assert(false && "Eve has been catched right away!")
    }

    // Restore skipped keys from the new ratchet-session
    var keys = self.stageSkippedKeys(Np, 0, HKp, CKp);

    // TODO(kudinkin): Coherent marshalling?
    body = util.unmarshalInt32Array(body);

    decrypted.body = self._decrypt(body, keys.MK)

    self.state.CKr = keys.CK;

    if (!body)
      throw "Undecipherable!";

    self.state.RK   = RKp;
    self.state.HKr  = HKp;
    self.state.NHKr = NHKp;
    self.state.DHRr = DHRp;
    
    self.state.RF = true;
  }

  // Commit skipped header-/message- keys to persistent storage
  self.commitSkippedKeys();

  self.state.Nr = Np + 1;

  // _DBG
  log.v(">> [x] DECRYPT: END >>>>>>>>>>>>>>>");

  return decrypted.body;

  // TODO(kudinkin): Decrypt headers to support V2 and ratcheting

  //var message_key = self.HMAC(self.state.CKr, "0");

  //  var decrypted = self._decrypt(bytes, message_key);
  //
  //  self.state.Ns += 1;
  //  self.state.CKs = self.HMAC(self.state.CKs, "1");
  //
  //  return decrypted;
}

Axolotl.prototype.probeSkippedKeys = function probeSkippedKeys(bytes, padding) {
  var self = this;

  var header  = bytes.slice(0, 106 - padding);
  var body    = bytes.slice(106);

  var decrypted = {};

  for (var i = 0; i < self.state.staged.length; ++i) {
    if (CHECK_WHETHER_DO_CONVERSATION_PARTIES_MATCH) {
      decrypted = {
        header: self._decrypt(header, self.staged[i].HKr),
        body:   self._decrypt(body,   self.staged[i].keys.MK)
      }

      if (decrypted.header && decrypted.body) {
        self.staged.splice(i--, 1);
        break;
      }
    }
  }

  return decrypted;
}

Axolotl.prototype.stageSkippedKeys = function stageSkippedKeys(N, Nr, HKr, CKr) {
  var self = this;

  log.t("STAGE SKIPPED N/Nr/HKr/CKr: ", N, Nr, HKr, CKr);

  var CK = CKr;
  var MK;

  for (var i = 0; i < N - Nr; ++i) {
    MK = self.HMAC(CK, "0");
    CK = self.HMAC(CK, "1")

    // TODO(kudinkin): Not really, WTF?
    self.staged[MK] = HKr;
  }

  return {
    MK: self.HMAC(CK, "0"),
    CK: self.HMAC(CK, "1")
  }
}

Axolotl.prototype.commitSkippedKeys = function commitSkippedKeys() {
  // NOP
}

Axolotl.prototype._decrypt = function _decrypt(bytes, key) {
  var c = new AES(key);

  var out = [];

  for (var i = 0; i < bytes.length; i += 4)
    Array.prototype.push.apply(out, c.decrypt(bytes.slice(i, i + 4)));

  log.t("DECRYPTED", out);

  return out;
}

Axolotl.prototype.HMAC = function HMAC_(key, m) {
  //return hash.sha256().update(key + m).digest();
  return new HMAC(key).encrypt(m);
}

Axolotl.prototype.PBKDF2 = function PBKDF2_(password, salt) {
  return PBKDF2(password, salt, 1000 /* rounds */, 256 /* length */);
}

Axolotl.prototype.tripleDH = function tripleDH(A, A0, B, B0) {
  //
  // A  - our identity key-pair  
  // A0 - our hand-shake key-pair
  // B  - their identity public-key
  // B0 - their hand-shake public-key
  //
  // The whole key-agreement scheme:
  // -------------------------------
  //   - Parties exchange identity keys (A, B) and handshake keys (A0, A1) and (B0, B1)
  //   - Parties assign "Alice" and "Bob" roles by comparing public keys
  //   - Parties calculate master key using tripleDH:
  //     - master_key = HASH( DH(A, B0) || DH(A0, B) || DH(A0, B0) )
  //

  var sha256 = hash.sha256();

  var DH = this.DH;

  if (this.mode === 'alice')
    sha256.update(DH(A, B0) + DH(A0, B) + DH(A0, B0));
  else if (this.mode === 'bob') 
    sha256.update(DH(A0, B) + DH(A, B0) + DH(A0, B0));
  else
    assert(false && "Eve has been catched right away!")

  return sha256.digest();
}

Axolotl.prototype.DH = function DH(kp, pub) {
  return kp.derive(pub);
}

Axolotl.prototype.generateKeyPair = function generateKeyPair() {
  return djb.genKeyPair();
}

