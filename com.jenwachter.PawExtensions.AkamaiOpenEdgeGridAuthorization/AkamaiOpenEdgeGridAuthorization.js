// https://paw.cloud/docs/dynamic-values/utils#Timestamp
function getTimestamp() {
  var dv = new DynamicValue('com.luckymarmot.TimestampDynamicValue', {
    now: true,
    format: 0,
    customFormat: '%Y%m%dT%H:%M:%S+0000'
  });
  return dv.getEvaluatedString();
}

// https://paw.cloud/docs/dynamic-values/utils#Nonce
function getNonce() {
  var dv = new DynamicValue('com.luckymarmot.NonceDynamicValue', {
    useUppercaseLetters: true,
    useHexDigits: true
  });
  return dv.getEvaluatedString();
}

// https://paw.cloud/docs/dynamic-values/encoding_crypto#HMAC_Signature
function signHmac256(key, input) {
  var dv = DynamicValue('com.luckymarmot.HMACDynamicValue', {
    input: input,
    key: key,
    algorithm: 3,
    uppercase: false,
    encoding: 'Base64'
  });
  return dv.getEvaluatedString();
}

// https://paw.cloud/docs/dynamic-values/encoding_crypto#Hash
function hash256(input) {
  var dv = DynamicValue('com.luckymarmot.HashDynamicValue', {
    input: input,
    hashType: 5,
    uppercase: false,
    encoding: 'Base64'
  });
  return dv.getEvaluatedString();
}

/**
 * Parses an URI
 * @author Steven Levithan <stevenlevithan.com> (MIT license)
 * https://github.com/get/parseuri
 */
function parseuri(str) {
  var re = /^(?:(?![^:@]+:[^:@\/]*@)(http|https|ws|wss):\/\/)?((?:(([^:@]*)(?::([^:@]*))?)?@)?((?:[a-f0-9]{0,4}:){2,7}[a-f0-9]{0,4}|[^:\/?#]*)(?::(\d*))?)(((\/(?:[^?#](?![^?#\/]*\.[^?#\/.]+(?:[?#]|$)))*\/?)?([^?#\/]*))(?:\?([^#]*))?(?:#(.*))?)/;
  var parts = ['source', 'protocol', 'authority', 'userInfo', 'user', 'password', 'host', 'port', 'relative', 'path', 'directory', 'file', 'query', 'anchor'];

  var src = str,
    b = str.indexOf('['),
    e = str.indexOf(']');

  if (b != -1 && e != -1) {
    str = str.substring(0, b) + str.substring(b, e).replace(/:/g, ';') + str.substring(e, str.length);
  }

  var m = re.exec(str || ''),
    uri = {},
    i = 14;

  while (i--) {
    uri[parts[i]] = m[i] || '';
  }

  if (b != -1 && e != -1) {
    uri.source = src;
    uri.host = uri.host.substring(1, uri.host.length - 1).replace(/;/g, ':');
    uri.authority = uri.authority.replace('[', '').replace(']', '').replace(/;/g, ':');
    uri.ipv6uri = true;
  }

  return uri;
}

function getSignature(key, request, authorization) {
  var parts = parseuri(request.url);
  return signHmac256(key, request.method + '\thttps\t' + parts.host + '\t' + parts.path + '\t\t' + hash256(request.body) + '\t' + authorization);
}

var AkamaiOpenEdgeGridAuthorization = function () {

  this.evaluate = function (context) {

    var timestamp = getTimestamp();

    var auth = 'EG1-HMAC-SHA256 client_token=' + this.client_token + ';';
    auth += 'access_token=' + this.access_token + ';';
    auth += 'timestamp=' + timestamp + ';';
    auth += 'nonce=' + getNonce() + ';';

    var key = signHmac256(this.client_secret, timestamp);
    var request = context.getCurrentRequest();

    var signature = getSignature(key, request, auth);
    auth += 'signature=' + signature;

    return auth;

  };

};

/**
 * API Client Authentication docs:
 * https://developer.akamai.com/introduction/Client_Auth.html
 */
AkamaiOpenEdgeGridAuthorization.identifier = 'com.jenwachter.PawExtensions.AkamaiOpenEdgeGridAuthorization';
AkamaiOpenEdgeGridAuthorization.title = 'Akamai EdgeGrid Authorization';
AkamaiOpenEdgeGridAuthorization.help = 'https://github.com/jenwachter/Paw-AkamaiOpenEdgeGridAuthorization';
AkamaiOpenEdgeGridAuthorization.inputs = [
    DynamicValueInput('client_token', 'Client Token', 'String'),
    DynamicValueInput('client_secret', 'Client Secret', 'SecureValue'),
    DynamicValueInput('access_token', 'Access Token', 'String')
];

registerDynamicValueClass(AkamaiOpenEdgeGridAuthorization);
