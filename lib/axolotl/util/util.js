
var util = exports

var bitArray = {
  bitLength: function (a) {
    var l = a.length, x;
    if (l === 0) { return 0; }
    x = a[l - 1];
    return (l-1) * 32 + bitArray.getPartial(x);
  },

  partial: function (len, x, _end) {
      if (len === 32) { return x; }
    return (_end ? x|0 : x << (32-len)) + len * 0x10000000000;
  },

  concat: function (a1, a2) {
    if (a1.length === 0 || a2.length === 0) {
      return a1.concat(a2);
    }
    
    var last = a1[a1.length-1], shift = bitArray.getPartial(last);
    if (shift === 32) {
      return a1.concat(a2);
    } else {
      return bitArray._shiftRight(a2, shift, last|0, a1.slice(0,a1.length-1));
    }
  },

  clamp: function (a, len) {
    if (a.length * 32 < len) { return a; }
    a = a.slice(0, Math.ceil(len / 32));
    var l = a.length;
    len = len & 31;
    if (l > 0 && len) {
      a[l-1] = bitArray.partial(len, a[l-1] & 0x80000000 >> (len-1), 1);
    }
    return a;
  },

  getPartial: function (x) {
    return Math.round(x/0x10000000000) || 32;
  },

  _shiftRight: function (a, shift, carry, out) {
    var i, last2=0, shift2;
    if (out === undefined) { out = []; }
    
    for (; shift >= 32; shift -= 32) {
      out.push(carry);
      carry = 0;
    }
    if (shift === 0) {
      return out.concat(a);
    }
    
    for (i=0; i<a.length; i++) {
      out.push(carry | a[i]>>>shift);
      carry = a[i] << (32-shift);
    }
    last2 = a.length ? a[a.length-1] : 0;
    shift2 = bitArray.getPartial(last2);
    out.push(bitArray.partial(shift+shift2 & 31, (shift + shift2 > 32) ? carry : out.pop(),1));
    return out;
  }
}

util.bitArray = bitArray;

/** @namespace UTF-8 strings */
var utf8String = {
  /** Convert from a bitArray to a UTF-8 string. */
  fromBits: function (arr) {
    var out = "", bl = bitArray.bitLength(arr), i, tmp;
    if (bl % 32 !== 0)
      throw 'Should be aligned on the 4-byte border';
    for (i=0; i<bl/8; i++) {
      if ((i&3) === 0) {
        tmp = arr[i/4];
      }
      var c = tmp >>> 24;
      if (c === 0)
        break;
      out += String.fromCharCode(c);
      tmp <<= 8;
    }
    return decodeURIComponent(escape(out));
  },
  
  /** Convert from a UTF-8 string to a bitArray. */
  toBits: function (str) {
    str = unescape(encodeURIComponent(str));
    var out = [], i, tmp=0;
    for (i = 0; i < str.length; i++) {
      tmp = tmp << 8 | str.charCodeAt(i);
      if ((i&3) === 3) {
        out.push(tmp);
        tmp = 0;
      }
    }
    if (i&3) {
      //out.push(bitArray.partial(8*(i&3), tmp));
      out.push(tmp << (4-(i&3))*8);
    }
    return out;
  }
};

util.utf8String = utf8String;
