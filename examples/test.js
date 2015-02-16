
var axolotl = require("../proto.js").proto

var alice = new axolotl("alice")
var bob   = new axolotl("bob")

alice .init(bob.introduce(),    /* Do not verify */ false);
bob   .init(alice.introduce(),  /* Do not verify */ false);

var eyo = alice.encrypt("Quick brown fox jumps over the lazy dog! 😸");
//var eyo = alice.encryptBytes([ 0, 1, 2, 3, 3, 2, 1 ]);

console.log(eyo);

var dyo = bob.decrypt(eyo);
//var dyo = bob.decryptBytes(eyo);

console.log(dyo);

