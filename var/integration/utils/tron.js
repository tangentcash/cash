const TronWeb = require('tronweb');
const ctx = new TronWeb.TronWeb({
    fullNode: 'http://localhost:8028',
    solidityNode: 'http://localhost:8027',
    eventServer: 'http://localhost:8029',
    privateKey: '7490a550b9edb6d4b3b66c04085c482d6450d92b6dd485f685f11dad4cfda3c8'
});
ctx.trx.sendTransaction('TU5HJSXLXswe7ZR8dpFgsoSGjitAEuaJ6V', 50 * 1000000).then(console.log).catch(console.error);