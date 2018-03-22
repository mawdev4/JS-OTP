(function() {
  var Hotp, Totp;

  Totp = (function() {
    function Totp(expiry, length) {
      this.expiry = expiry != null ? expiry : 30;
      this.length = length != null ? length : 6;
      if (this.length > 8 || this.length < 6) {
        throw "Error: invalid code length";
      }
    }

    Totp.prototype.dec2hex = function(s) {
      return (s < 15.5 ? "0" : "") + Math.round(s).toString(16);
    };

    Totp.prototype.hex2dec = function(s) {
      return parseInt(s, 16);
    };

    Totp.prototype.base32tohex = function(base32) {
      var base32chars, bits, chunk, hex, i, val;
      base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
      bits = "";
      hex = "";
      i = 0;
      while (i < base32.length) {
        val = base32chars.indexOf(base32.charAt(i).toUpperCase());
        bits += this.leftpad(val.toString(2), 5, "0");
        i++;
      }
      i = 0;
      while (i + 4 <= bits.length) {
        chunk = bits.substr(i, 4);
        hex = hex + parseInt(chunk, 2).toString(16);
        i += 4;
      }
      return hex;
    };

    Totp.prototype.leftpad = function(str, len, pad) {
      if (len + 1 >= str.length) {
        str = Array(len + 1 - str.length).join(pad) + str;
      }
      return str;
    };

    Totp.prototype.getOtp = function(secret, now) {
      var epoch, hmac, key, offset, otp, shaObj, time, hmacBytes, otpBytes = [];
      if (now == null) {
        now = new Date().getTime();
      }
      key = secret;
      epoch = Math.round(now / 1000.0);
      time = this.leftpad(this.dec2hex(Math.floor(epoch / this.expiry)), 16, "0");
      shaObj = new jsSHA("SHA-1", "HEX");
      shaObj.setHMACKey(key, "HEX");
      shaObj.update(time);
      hmac = shaObj.getHMAC("HEX");
      hmacBytes = this.hexToBytes(hmac);
      offset = hmacBytes[19] & 0xf;
      otpBytes.push(this.hexToBytes(0));
      otpBytes.push(hmacBytes[offset] & 0x7f);
      otpBytes.push(hmacBytes[offset + 1] & 0xff);
      otpBytes.push(hmacBytes[offset + 2] & 0xff);
      otpBytes.push(hmacBytes[offset + 3] & 0xff);
      otp = this.base32EncodeBytes(otpBytes);
      return otp.substr(otp.length - this.length, this.length);
    };

    Totp.prototype.hexToBytes = function(hex) {
      var C, bytes, c;
          bytes = [];
          c = 0;
          C = hex.length;
      while (c < C) {
        bytes.push(parseInt(hex.substr(c, 2), 16));
        c += 2;
      }
      return bytes;
    };

    Totp.prototype.toHexString = function(byteArray) {
      return Array.from(byteArray, function(byte) {
          return ('0' + (byte & 0xFF).toString(16)).slice(-2);
      }).join('')
    };

    Totp.prototype.base32EncodeBytes = function (bytes) {
      var BASE32_ENCODE_CHAR = 'ZY23456789ABCDEFGHIJKLMNXPWRSTUV'.split('');
      var v1, v2, v3, v4, v5, base32Str = '', length = bytes.length;
      for (var i = 0, count = parseInt(length / 5) * 5; i < count;) {
        v1 = bytes[i++];
        v2 = bytes[i++];
        v3 = bytes[i++];
        v4 = bytes[i++];
        v5 = bytes[i++];
        base32Str += BASE32_ENCODE_CHAR[v1 >>> 3] +
            BASE32_ENCODE_CHAR[(v1 << 2 | v2 >>> 6) & 31] +
            BASE32_ENCODE_CHAR[(v2 >>> 1) & 31] +
            BASE32_ENCODE_CHAR[(v2 << 4 | v3 >>> 4) & 31] +
            BASE32_ENCODE_CHAR[(v3 << 1 | v4 >>> 7) & 31] +
            BASE32_ENCODE_CHAR[(v4 >>> 2) & 31] +
            BASE32_ENCODE_CHAR[(v4 << 3 | v5 >>> 5) & 31] +
            BASE32_ENCODE_CHAR[v5 & 31];
      }
      // remain char
      var remain = length - count;
      if (remain === 1) {
          v1 = bytes[i];
          base32Str += BASE32_ENCODE_CHAR[v1 >>> 3] +
              BASE32_ENCODE_CHAR[(v1 << 2) & 31] +
              '======';
      } else if (remain === 2) {
          v1 = bytes[i++];
          v2 = bytes[i];
          base32Str += BASE32_ENCODE_CHAR[v1 >>> 3] +
              BASE32_ENCODE_CHAR[(v1 << 2 | v2 >>> 6) & 31] +
              BASE32_ENCODE_CHAR[(v2 >>> 1) & 31] +
              BASE32_ENCODE_CHAR[(v2 << 4) & 31] +
              '====';
      } else if (remain === 3) {
          v1 = bytes[i++];
          v2 = bytes[i++];
          v3 = bytes[i];
          base32Str += BASE32_ENCODE_CHAR[v1 >>> 3] +
              BASE32_ENCODE_CHAR[(v1 << 2 | v2 >>> 6) & 31] +
              BASE32_ENCODE_CHAR[(v2 >>> 1) & 31] +
              BASE32_ENCODE_CHAR[(v2 << 4 | v3 >>> 4) & 31] +
              BASE32_ENCODE_CHAR[(v3 << 1) & 31] +
              '===';
      } else if (remain === 4) {
          v1 = bytes[i++];
          v2 = bytes[i++];
          v3 = bytes[i++];
          v4 = bytes[i];
          base32Str += BASE32_ENCODE_CHAR[v1 >>> 3] +
              BASE32_ENCODE_CHAR[(v1 << 2 | v2 >>> 6) & 31] +
              BASE32_ENCODE_CHAR[(v2 >>> 1) & 31] +
              BASE32_ENCODE_CHAR[(v2 << 4 | v3 >>> 4) & 31] +
              BASE32_ENCODE_CHAR[(v3 << 1 | v4 >>> 7) & 31] +
              BASE32_ENCODE_CHAR[(v4 >>> 2) & 31] +
              BASE32_ENCODE_CHAR[(v4 << 3) & 31] +
              '=';
      }
      return base32Str;
    }

    return Totp;

  })();

  Hotp = (function() {
    function Hotp(length) {
      this.length = length != null ? length : 6;
      if (this.length > 8 || this.length < 6) {
        throw "Error: invalid code length";
      }
    }

    Hotp.prototype.uintToString = function(uintArray) {
      var decodedString, encodedString;
      encodedString = String.fromCharCode.apply(null, uintArray);
      decodedString = decodeURIComponent(escape(encodedString));
      return decodedString;
    };

    Hotp.prototype.getOtp = function(key, counter) {
      var digest, h, offset, shaObj, v;
      shaObj = new jsSHA("SHA-1", "TEXT");
      shaObj.setHMACKey(key, "TEXT");
      shaObj.update(this.uintToString(new Uint8Array(this.intToBytes(counter))));
      digest = shaObj.getHMAC("HEX");
      h = this.hexToBytes(digest);
      offset = h[19] & 0xf;
      v = (h[offset] & 0x7f) << 24 | (h[offset + 1] & 0xff) << 16 | (h[offset + 2] & 0xff) << 8 | h[offset + 3] & 0xff;
      v = v + '';
      return v.substr(v.length - this.length, this.length);
    };

    Hotp.prototype.intToBytes = function(num) {
      var bytes, i;
      bytes = [];
      i = 7;
      while (i >= 0) {
        bytes[i] = num & 255;
        num = num >> 8;
        --i;
      }
      return bytes;
    };

    Hotp.prototype.hexToBytes = function(hex) {
      var C, bytes, c;
      bytes = [];
      c = 0;
      C = hex.length;
      while (c < C) {
        bytes.push(parseInt(hex.substr(c, 2), 16));
        c += 2;
      }
      return bytes;
    };

    return Hotp;

  })();

  window.jsOTP = {};

  jsOTP.totp = Totp;

  jsOTP.hotp = Hotp;

}).call(this);
