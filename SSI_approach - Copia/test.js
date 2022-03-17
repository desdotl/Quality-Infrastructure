var myBuffer = [];
var str = 'Stack Overflow';
var buffer = new Buffer(str, '0xutf16le'.slice(2));
console.log('0xutf16le'.slice(2));
for (var i = 0; i < buffer.length; i++) {
    myBuffer.push(buffer[i].toString(16));
}

console.log(myBuffer);