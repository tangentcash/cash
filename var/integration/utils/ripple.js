const xrpl = require('xrpl');

async function main() {
    console.log("Connecting to Testnet...");
    const client = new xrpl.Client('wss://s.altnet.rippletest.net:51233');
    await client.connect();

    console.log("Getting a funded wallet...");
    const amount = 50;
    const wallet = xrpl.Wallet.fromSecret('sEdV3k8XxKKWALLjEvX8FyxEq4AoTqf');
    const balance = await client.getXrpBalance(wallet.address);
    if (balance < amount) {
        const result = await client.fundWallet(wallet);
        console.log(result);
    }

    console.log("Preparing a wallet transaction...");
    const prepared = await client.autofill({
        "TransactionType": "Payment",
        "Account": wallet.address,
        "Amount": xrpl.xrpToDrops(amount),
        "Destination": 'r43WimWjQUqNN31EekAAp5MJYwHrMvPCg2',
        "DestinationTag": parseInt(1)
    });
    const max_ledger = prepared.LastLedgerSequence;
    console.log("Prepared transaction instructions:", prepared);
    console.log("Transaction cost:", xrpl.dropsToXrp(prepared.Fee), "XRP");
    console.log("Transaction expires after ledger:", max_ledger);

    const signed = wallet.sign(prepared);
    console.log("Identifying hash:", signed.hash);
    console.log("Signed blob:", signed.tx_blob)

    const tx = await client.submitAndWait(signed.tx_blob);
    console.log("Transaction result:", tx.result.meta.TransactionResult);
    console.log("Balance changes:", JSON.stringify(xrpl.getBalanceChanges(tx.result.meta), null, 2));

    client.disconnect();
}

main().then(() => process.exit(0));