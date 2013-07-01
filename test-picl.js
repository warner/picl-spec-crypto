const srp = require("./index.js");

var N = srp.params["2048"].N;
var g = srp.params["2048"].g;
var emailUTF8 = new Buffer("andré@example.org", "utf8");
var passwordUTF8 = new Buffer("pässwörd", "utf8");
console.log(emailUTF8.toString("hex"));
console.log(passwordUTF8.toString("hex"));

function fakeKeyArray(start) {
    var a = [];
    for (var i=start; i<start+32; i++)
        a.push(i);
    return a;
}

var srpSalt = new Buffer(fakeKeyArray(0));
console.log(srpSalt.toString("hex"));

var srpVerifier = srp.getv(srpSalt, emailUTF8, passwordUTF8, N, g, "sha256");
console.log(srpVerifier.toString("hex"));
