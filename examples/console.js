
var axolotl = require("../lib/axolotl.js").axolotl;

var alice = new axolotl("alice")
var bob   = new axolotl("bob")

alice .init(bob.introduce(),    /* Do not verify */ false);
bob   .init(alice.introduce(),  /* Do not verify */ false);

function sendBob(line) {
  if (!bob.mbx)
    bob.mbx = new Array(); 
  bob.mbx.push(bob.decrypt(alice.encrypt(line)));
}

function sendAlice(line) {
  if (!alice.mbx)
    alice.mbx = new Array(); 
  alice.mbx.push(alice.decrypt(bob.encrypt(line)));
}

function replayBob() {
  bob.mbx.forEach(function (m) {
    console.log("# Alice: ", m);
  });

  bob.mbx = null;
}

function replayAlice() {
  alice.mbx.forEach(function (m) {
    console.log("# Bob: ", m);
  });

  alice.mbx = null;
}

// # Alice
sendBob("Ola, Bob!");
sendBob("How're you?");
sendBob("What's up?");
replayBob();

// # Bob 
sendAlice("I'm fine!");
sendAlice("And you?");
replayAlice();

// # Alice 
sendBob("Cool!");
sendBob("I'm fine too, Bob");
replayBob();


// Make a prompt
//var readline = require("readline");
//
//var rl = readline.createInterface({
//  input:  process.stdin,
//  output: process.stdout
//});

//rl.prompt();
//rl.on('line', function (l) {
//  if (l === 'exit')
//    rl.close();
//
//  console.log("Echo: ", sendBob(l));
//
//  rl.prompt();
//}).on('close', function () {
//  process.exit(0);
//});

