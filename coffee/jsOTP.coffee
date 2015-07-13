class TotpManager
  # pass in the secret, code dom element, ticker dom element
  constructor: (@expiry = 30, @length = 6) ->
    # validate input
    if @length > 8 or @length < 6
      throw "Error: invalid code length"

  dec2hex: (s) ->
    ((if s < 15.5 then "0" else "")) + Math.round(s).toString(16)
  
  hex2dec: (s) ->
    parseInt s, 16
  
  base32tohex: (base32) ->
    base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    bits = ""
    hex = ""
  
    i = 0
    while i < base32.length
      val = base32chars.indexOf(base32.charAt(i).toUpperCase())
      bits += @leftpad(val.toString(2), 5, "0")
      i++
  
    i = 0
    while i + 4 <= bits.length
      chunk = bits.substr(i, 4)
      hex = hex + parseInt(chunk, 2).toString(16)
      i += 4
    return hex
  
  leftpad: (str, len, pad) ->
    str = Array(len + 1 - str.length).join(pad) + str  if len + 1 >= str.length
    return str
  
  getOtp: (secret) ->
    key = @base32tohex(secret)
    epoch = Math.round(new Date().getTime() / 1000.0)
    time = @leftpad(@dec2hex(Math.floor(epoch / @expiry)), 16, "0")
    hmacObj = new jsSHA(time, "HEX")  # Dependency on sha.js
    hmac = hmacObj.getHMAC(key, "HEX", "SHA-1", "HEX")
  
    if hmac is "KEY MUST BE IN BYTE INCREMENTS"
      throw "Error: hex key must be in byte increments"
      # return null
    else
      offset = @hex2dec(hmac.substring(hmac.length - 1))
  
    otp = (@hex2dec(hmac.substr(offset * 2, 8)) & @hex2dec("7fffffff")) + ""
    otp = (otp).substr(otp.length - @length, @length)
    return otp
  

window.TotpManager = TotpManager