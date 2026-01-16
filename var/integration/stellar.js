const fetch = require('node-fetch')
const StellarSdk = require("stellar-sdk")
const util = require('util')

async function main() {
    console.log("Connecting to Testnet...");
    const server = new StellarSdk.Server("https://horizon-testnet.stellar.org")

    console.log("Getting a funded wallet...");
    const amount = 50;
    const wallet = StellarSdk.Keypair.fromSecret('SA5VGMZ5ATMZMJ4223IW6FFVT364RL4TLM6PI7KXBSCX4DFYBKSSPP4T');
    let account, balance;
    try {
        account = await server.loadAccount(wallet.publicKey());
        balance = parseFloat((account.balances.filter((v) => v.asset_type == 'native')[0] || { balance: '0' }).balance);
        if (balance < amount)
            throw false;
    } catch {
        await fetch('https://friendbot.stellar.org?addr=' + encodeURIComponent(wallet.publicKey()));
        account = await server.loadAccount(wallet.publicKey());
        balance = parseFloat((account.balances.filter((v) => v.asset_type == 'native')[0] || { balance: '0' }).balance);
        console.log({
            wallet: {
                address: wallet.publicKey(),
                secret: wallet.secret()
            },
            balance: balance
        });
    }

    const fee = await server.fetchBaseFee();
    const builder = new StellarSdk.TransactionBuilder(account, {
        fee: fee,
        networkPassphrase: StellarSdk.Networks.TESTNET
    });
    
    const toAddress = 'GBDR34YVWCZKRI6NSFCPZZBKXQR2B3QKJMNKGP6JCCHOP4URSRX46JPZ';
    const toMemo = '1';
    try {
        await server.loadAccount(toAddress);
        builder.addOperation(StellarSdk.Operation.payment({
            destination: toAddress,
            asset: StellarSdk.Asset.native(),
            amount: amount.toString()
        }));
    } catch {
        builder.addOperation(StellarSdk.Operation.createAccount({
            destination: toAddress,
            startingBalance: amount.toString()
        }));
    }
    builder.addMemo(StellarSdk.Memo.text(toMemo));

    const transaction = builder.setTimeout(30).build();
    transaction.sign(wallet);
    console.log('Prepared transaction:', util.inspect(transaction, { showHidden: false, depth: null, colors: true }));
    console.log('Raw XDR envelope data:', transaction.toXDR());
    console.log('Raw XDR envelope hash:', transaction.hash().toString('hex'));
    try
    {
        const result = await server.submitTransaction(transaction);
        console.log('Sent prepared transaction:', util.inspect(result, { showHidden: false, depth: null, colors: true }));
    }
    catch (err)
    {
        console.error('Cannot send transaction:', util.inspect(err, { showHidden: false, depth: null, colors: true }));
    }
}

main().then(() => process.exit(0));