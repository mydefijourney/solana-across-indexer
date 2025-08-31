import fs from 'fs';
import Redis from 'ioredis';
import axios from 'axios';
import dotenv from 'dotenv';
import mysql, { Connection } from 'mysql2/promise';
import { RowDataPacket, OkPacket  } from 'mysql2';
import { Connection, PublicKey, clusterApiUrl, Keypair, SystemProgram, Transaction, sendAndConfirmTransaction } from "@solana/web3.js";
import { getAccount, getAssociatedTokenAddress, getAssociatedTokenAddressSync, TOKEN_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID, getOrCreateAssociatedTokenAccount, getMint, createApproveCheckedInstruction } from "@solana/spl-token";
import { isAddress} from "@solana/kit";
import * as anchor from "@coral-xyz/anchor";
import { web3, BN, AnchorProvider, Program, BorshEventCoder, Idl } from "@coral-xyz/anchor";
import bs58 from "bs58";
import { Buffer } from "buffer";
import { ethers } from 'ethers';
import { logMessage, hexToAddress, hexToBytes32, hexToDecimal, intToU8Array32, calculateRelayHashUint8Array, getFillRelayDelegatePda, FillDataValues, getEvmRelayHash, decodeEvmDeposit } from './functions';
import { execSync } from "child_process";
import WebSocket from 'ws';
import * as bip39 from "bip39";
import * as ed25519 from "ed25519-hd-key";
import { SvmSpokeIdl } from "@across-protocol/contracts";

const relayerStartTime = new Date();
logMessage("Starting Solana relayer", "greenbold");
logMessage("\n.....................................................................................\n.....................................................................................\n.....................................................................................\n.....................................................................................\n.....................................................................................\n.............................:oxdl,...........................,oO0Od;................\n............................dNMMMW0:.........................'kWMMMMO,...............\n................'ldolc;,'..'OMMMMMNo..........................xNMMMWk'...............\n...............l0WWWWWWNX0xloOXNX0o'.....................;cloodkOkdc'................\n.............;kNWKdccdKWMMMWXOd:,...................,:ok0NWMMMWNKd,..................\n............;0WXd,...lKMMMMMMMNOc...........;:'';lx0XWWX00NMMMMMMW0c.................\n.............cl;...'dNMMMMMMNXNMNk:'.....';lxxOKNNXOxo:,'oNMMMMMWWMXo,',,;'..........\n..................;kWMMMMMW0c,cONWNKOxoclxkd,,ldl:'.....:KMMMMMXdoKMWXXXNXO;.........\n.................,OWMMMMMNx,....:dk0KNWWNx;............'kWMMMMWx..;dkxdolc;..........\n.................,OWMMMMKl..........'lOxc'.............oNMMMMM0;.....................\n.................:0WMMMM0:............'...............:KMMWMMM0:.....................\n..............',oKWMWNWMMXo'.........................,OWMNxkNMWKc....................\n........:odxO0KNWMMXo;lKWMWO;..................,;cldx0WMWx..cKWMXo...................\n.......cKWWWNNXXK0x:...cXMMXl................c0XNWWWWNXKd'...,kWMNo..................\n........:cc:;,,'.......dNMNx'................;dxxolc:;,.......,OMM0,.................\n......................lXMWk,...................................cXMNo.................\n.....................;0MWO,....................................'xWM0,................\n.....................;kKk;......................................,kKk,................\n.......................'..........................................'..................\n.....................................................................................\n.....................................................................................\n.....................................................................................\n","purple");

// get the main configs
loadEncryptedEnv();

const connectionData = {
	host: process.env.MYSQL_HOST,
	port: Number(process.env.MYSQL_PORT),
	user: process.env.MYSQL_USER,
	password: process.env.MYSQL_PASS,
	database: process.env.MYSQL_DB,
	ssl: {
		ca: fs.readFileSync('../relayer/certs/ca-certificate.crt' as string),
	},
};
export default connectionData;
let dbConnection: Connection;
connectMysql();

const mainConfigRaw = fs.readFileSync("../relayer/configurations/main.json", 'utf-8');
const mainConfig = JSON.parse(mainConfigRaw);
logMessage("✅ Main config loaded");

const tokenConfigRaw = fs.readFileSync("../relayer/configurations/tokens.json", 'utf-8');
const tokenConfig = JSON.parse(tokenConfigRaw);
//console.log(tokenConfigRaw);
logMessage("✅ Token config loaded");

// load the initial blacklist, we will reload this every hour
let blacklistRaw = fs.readFileSync("../relayer/cache/blacklist.txt", 'utf-8');
let blacklist = blacklistRaw.split('\n');
let blacklistLowercase = blacklist.map(address => address.toLowerCase());
logMessage("✅ Blacklist loaded");
setInterval(updateBlacklist, 1 * 60 * 60 * 1000);

// initialize redis to cache gas prices
const redisClient = Redis.createClient();
const redisExp = 14400; // expire keys after 4h
initializeRedis();

let enabledChains = mainConfig.variables.enabledChains;
enabledChains = [1,10,56,130,137,324,480,8453,42161,7777777];
let solanaChainId = 34268394551451;

let currentDate = new Date();

const sendRelays = process.env.SEND_RELAYS || mainConfig.variables.sendRelays;
logMessage("💸 Sending relays: " + sendRelays);

// load wallet + USDC
const mnemonic = process.env[`MNEMONIC_4`] + '';
const USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"; // mainnet USDC mint

let wallet : any;
let relayerHexAddress : any;
let provider : AnchorProvider;
let program : Program;
let programId : web3.PublicKey;
let evmRepaymentAddress : string = '0x000000000000000000000000394311a6aaa0d8e3411d8b62de4578d41322d1bd'
loadWallet();
const connection = new Connection(clusterApiUrl("mainnet-beta"), "confirmed");
setTimeout(updateUsdcBalance,1000);
setInterval(updateUsdcBalance, 1 * 60 * 1000);

setTimeout(findPdasToClose, 10000);
setInterval(findPdasToClose, 1 * 60 * 1000);

connectWebSocket();

async function connectWebSocket() { 
    const ws = new WebSocket("ws://10.116.0.5:3332");
    ws.onopen = () => { 
        logMessage("✅ Connected to Stats Server Scraper WebSocket");
    }
    ws.onmessage = (event) => { 
        if(event) {
            console.log(event);
        }
    }
    ws.onclose = async() => { 
        logMessage("❌ Disconnected from WebSocket, try again in 15s", "red");
        await customSleep(15000);
        connectWebSocket();
    }
    ws.onmessage = (event) => {
        if(event.data) { 
            try { 
                //console.log(event.data);
                const data = JSON.parse(event.data.toString());
                //console.log(data);
                if(data.type == 'DEPOSIT') { 
                    processDeposit(data.data);
                }
            } catch(err) { 
                
            }
            
        }
    } 
    ws.onerror = async(event) => { 
        logMessage("❌ Error on WebSocket, try again in 15s", "red");
        ws.close();
        console.log(event);
        //await customSleep(15000);
        //connectWebSocket();
    }
}


async function processDeposit(deposit: any) { 
    //console.log(deposit);

    const depositId = Number(deposit.depositId.hex).toString();
    const originChainName = mainConfig.chainNames[`${deposit.originChainId}`];
    const destinationChainName = mainConfig.chainNames[`${Number(deposit.destinationChainId.hex)}`];

    let encodedData = '';
    let relayHash = '';
    let depositStatement = '';
    
    // get ranges
    const rawRangeJson = fs.readFileSync("../relayer/configurations/ranges.json", 'utf-8');
    const rangeJsonData = JSON.parse(rawRangeJson);

    // get prices
    const pricesFilePath = '../relayer/configurations/prices.json';
    const rawPriceJson = fs.readFileSync(pricesFilePath, 'utf-8');
    let pricesJsonData = JSON.parse(rawPriceJson);
    // format the token amount
    let tokenDecimals = Math.pow(10,tokenConfig[`${deposit.tokenName}`]?.decimals) || 1e18;
    let destTokenDecimals = tokenDecimals; 

    // specific to BNB chain
    if((deposit.outputTokenName == 'USDC' || deposit.outputTokenName == 'USDT') && deposit.originChainId == 56) {
        tokenDecimals = 1e18;
    }

    const tokenPrice = pricesJsonData[deposit.outputTokenName];
    const usdValue = (Number(deposit.outputAmount)/destTokenDecimals) * tokenPrice;

    depositStatement = `${depositId}: ${(deposit.inputAmount/tokenDecimals).toFixed(6)} ${deposit.tokenName} from ${originChainName} to ${(deposit.outputAmount/destTokenDecimals).toFixed(6)} ${deposit.outputTokenName} on ${destinationChainName}`;

    let okToContinue = 1;

    if(okToContinue == 1 && deposit.outputTokenName != 'USDC') { 
        okToContinue = 0;
        //logMessage(`${depositId}: ❌ Not a USDC deposit, skipping`, "red");
        return;
    }
    if(okToContinue == 1 && destinationChainName != 'Solana') { 
        okToContinue = 0;
        //logMessage(`${depositId}: ❌ Not a Solana-destination deposit, skipping`, "red");
        return;
    }

    if(okToContinue == 1) { 
        logMessage("");
        logMessage(depositStatement, "blue");
    }

    if(okToContinue == 1 && !enabledChains.includes(deposit.originChainId)) { 
        okToContinue = 0;
        logMessage(`${depositId}: ❌ ${originChainName} not enabled as an origin chain`, "red");
    }
    
    if(okToContinue == 1) { 
        // check raw bps
        let originAmount = deposit.inputAmount;
        if(deposit.originChainId == 56) { 
            originAmount = deposit.inputAmount/1e12;
        }
        let destinationAmount = deposit.outputAmount;

        let rawBps = ((originAmount-destinationAmount)/originAmount)*100;
        let rawBpsFormatted = (rawBps * 100).toFixed(2);
        logMessage(`${depositId}: Raw bps: ${rawBps.toFixed(4)}% - ${rawBpsFormatted} BPS`, "yellow");
        if(rawBps < 0.02) { 
            logMessage(`${depositId}: ❌ Raw bps fee too low`, "yellow");
            okToContinue = 0;
        }
    }  
    if(okToContinue == 1 && deposit.message != '0x') { 
        okToContinue = 0;
        logMessage(`${depositId}: ❌ Deposit contains message, skipping for now`, "red");
    }
    if(okToContinue == 1 && deposit.tokenName != deposit.outputTokenName) { 
        okToContinue = 0;
        logMessage(`${depositId}: ❌ Token name mismatch, skipping`, "red");
    }
    // blacklist
    if(okToContinue == 1) { 
        if(blacklistLowercase.includes(deposit.recipient.toLowerCase()) || blacklistLowercase.includes(deposit.depositor.toLowerCase())) { 
            okToContinue = 0;
            logMessage(`${depositId}: ❌ Ignoring address on blacklist: ${deposit.recipient} (recipient) or ${deposit.depositor} (depositor)`,"red");
        }
    }
    if(okToContinue == 1) { 
        let currentMaxAmount = rangeJsonData[`${deposit.outputTokenName}`][`${Number(deposit.destinationChainId.hex)}`].maxDestinationAmount;
        let compareAmount = deposit.outputAmount/1e6;
        
        if(compareAmount > currentMaxAmount) { 
            logMessage(`${depositId}: ❌ amount is outside configured range (${compareAmount} vs ${currentMaxAmount})`, "yellow");
            okToContinue = 0;
        }
    }
    if(okToContinue == 1) { 
        // check balance
        let balance = await redisClient.get(`${wallet.publicKey.toBase58()}_${solanaChainId}_${deposit.outputTokenName}`);
        if(balance) { 
            if(Number(balance) < deposit.outputAmount) { 
                logMessage(`${depositId}: ❌ Insufficient balance: ${Number(balance)/1e6} USDC`, "yellow");
                okToContinue = 0;
            }
        } else { 
            logMessage(`${depositId}: ❌ No balance found for ${wallet.publicKey.toBase58()} on ${solanaChainId} ${deposit.outputTokenName}`, "yellow");
            okToContinue = 0;
        }
    }

    
    // TODO: do we have to wait? 
    if(originChainName == 'Mainnet' || originChainName == 'Polygon') {

        // based on usd value

        let minConfirmations = mainConfig.minDepositConfirmations.default[`${deposit.originChainId}`];
        for(const key in mainConfig.minDepositConfirmations) { 
            if(Number(key) > Number(usdValue)) { 
                if(mainConfig.minDepositConfirmations[key].hasOwnProperty(deposit.originChainId)) { 
                    minConfirmations = mainConfig.minDepositConfirmations[key][`${deposit.originChainId}`];
                    break;
                }
            }
        }
        if(minConfirmations == 0) { 
            minConfirmations = 1;
        }
        let targetBlock = Number(deposit.blockNumber) + minConfirmations;
        logMessage(`${depositId}: ${minConfirmations} confirmation(s) needed for $${usdValue.toFixed(2)} in value on ${originChainName}`);
        logMessage(`${depositId}: Deposit Block Number: ${deposit.blockNumber}`);
        logMessage(`${depositId}: Target Block Number:  ${targetBlock}`);

        await blockCounter(depositId, deposit.originChainId, deposit.blockNumber, targetBlock);
        // once block count has been reached, get a copy of the deposit receipt and decode it. If it doesn't match, abort

        let quorumMet = await runQuorumCheck(depositId, deposit);

        if(quorumMet == false) { 
            logMessage(`${depositId}: Quorum not met, skipping`, "red");
            okToContinue = 0;
        }


        // how long to wait/sleep? 
        // start a block counter?
        // quorum
    } 

    if(okToContinue == 1 && deposit.exclusiveRelayer != '0x0000000000000000000000000000000000000000' && deposit.exclusiveRelayer.toLowerCase() != relayerHexAddress.toLowerCase()) { 
        // not the exclusive relayer, determine if we have to wait
        logMessage(`${depositId}: Exclusive relayer assigned: ${deposit.exclusiveRelayer}`, "yellow");

        // how much time does this exclusive relayer have? 
        let exclusivityDeadline = deposit.exclusivityDeadline;
        let exclusivityDeadlineDate = new Date(exclusivityDeadline * 1000);
        let timeUntilExclusivityDeadline = exclusivityDeadlineDate.getTime() - Date.now();
        // how many seconds until exclusivity deadline? 
        let secondsUntilExclusivityDeadline = timeUntilExclusivityDeadline / 1000;
        logMessage(`${depositId}: Seconds until exclusivity deadline: ${secondsUntilExclusivityDeadline}`, "yellow");

        // if secondsUntilExclusivityDeadline is less than 0, then the deposit is expired
        if(secondsUntilExclusivityDeadline < 0) { 
            logMessage(`${depositId}: Exclusivity deadline has passed, go now`, "yellow");
        } else { 
            await customSleep(secondsUntilExclusivityDeadline);
            logMessage(`${depositId}: Exclusivity deadline has passed, go now`, "yellow");
        }
    }


    if(okToContinue == 1) { 
        //console.log(deposit);
        // put together the fill data: 
        const depositor = new PublicKey(evmToSolanaPK(deposit.depositor));
        const recipient = new PublicKey(hexToSolanaPK(deposit.recipient));
        const exclusiveRelayer = new PublicKey(hexToSolanaPK(deposit.exclusiveRelayer));
        const inputToken = new PublicKey(evmToSolanaPK(deposit.inputToken));
        const outputToken = new PublicKey(hexToSolanaPK(deposit.outputToken)); 
        const inputAmount = intToU8Array32(new BN(deposit.inputAmount));
        const outputAmount = new BN(deposit.outputAmount);
        const originChainId = new BN(deposit.originChainId);
        const depositIdForFill = intToU8Array32(new BN(Number(deposit.depositId.hex).toString()));
        const fillDeadline = deposit.fillDeadline;
        const exclusivityDeadline = deposit.exclusivityDeadline;
        const message = Buffer.from("");
        const seed = new BN('0'); // WHAT IS THIS

        const relayData = {
            depositor,
            recipient,
            exclusiveRelayer,
            inputToken,
            outputToken,
            inputAmount,
            outputAmount,
            originChainId,
            depositId: depositIdForFill,
            fillDeadline,
            exclusivityDeadline,
            message,
        };
        
        const signer = wallet;

        // fill the relay
        logMessage(`${depositId}: Filling relay`);
        // Define the state account PDA
        const [statePda, _] = PublicKey.findProgramAddressSync(
            [Buffer.from("state"), seed.toArrayLike(Buffer, "le", 8)],
            programId
        );

        // Fetch the state from the on-chain program to get chainId
        const state = await program.account.state.fetch(statePda);
        const chainId = new BN(state.chainId);

        const relayHashUint8Array = calculateRelayHashUint8Array(relayData, chainId);

        // Define the fill status account PDA
        const [fillStatusPda] = PublicKey.findProgramAddressSync([Buffer.from("fills"), relayHashUint8Array], programId);

        // Create ATA for the relayer and recipient token accounts
        const relayerTokenAccount = getAssociatedTokenAddressSync(
            outputToken,
            signer.publicKey,
            true,
            TOKEN_PROGRAM_ID,
            ASSOCIATED_TOKEN_PROGRAM_ID
        );

        const recipientTokenAccount = (
            await getOrCreateAssociatedTokenAccount(
              provider.connection,
              signer,
              outputToken,
              recipient,
              true,
              undefined,
              undefined,
              TOKEN_PROGRAM_ID,
              ASSOCIATED_TOKEN_PROGRAM_ID
            )
          ).address;

          /* 
          console.table([
            { property: "relayHash", value: Buffer.from(relayHashUint8Array).toString("hex") },
            { property: "chainId", value: chainId.toString() },
            { property: "programId", value: programId.toString() },
            { property: "providerPublicKey", value: provider.wallet.publicKey.toString() },
            { property: "statePda", value: statePda.toString() },
            { property: "fillStatusPda", value: fillStatusPda.toString() },
            { property: "relayerTokenAccount", value: relayerTokenAccount.toString() },
            { property: "recipientTokenAccount", value: recipientTokenAccount.toString() },
            { property: "seed", value: seed.toString() },
          ]);
          */

          logMessage(`${depositId}: Relay Data:`);
          console.table(
            Object.entries(relayData).map(([key, value]) => ({
              key,
              value: value.toString(),
            }))
          );
        
        const tokenDecimals = (await getMint(provider.connection, outputToken, undefined, TOKEN_PROGRAM_ID)).decimals;


          // Create the ATA using the create_token_accounts method
        const createTokenAccountsIx = await program.methods
            .createTokenAccounts()
            .accounts({ signer: signer.publicKey, mint: outputToken, tokenProgram: TOKEN_PROGRAM_ID })
            .remainingAccounts([
              { pubkey: recipient, isWritable: false, isSigner: false },
              { pubkey: recipientTokenAccount, isWritable: true, isSigner: false },
            ])
            .instruction();

        let repaymentChainId = chainId;
        let repaymentAddress = signer.publicKey;
        if(rangeJsonData[`${deposit.outputTokenName}`][`${solanaChainId}`].originRepayments && rangeJsonData[`${deposit.outputTokenName}`][`${solanaChainId}`].originRepayments == true) { 
            repaymentChainId = new BN(deposit.originChainId);
            repaymentAddress = new PublicKey(hexToSolanaPK(evmRepaymentAddress));
            logMessage(`${depositId}: Repayment: ${evmRepaymentAddress} on ${deposit.originChainId}`, "yellow");
        } else { 
            logMessage(`${depositId}: Repayment: ${signer.publicKey.toString()} on ${chainId}`, "yellow");
        }


        const delegate = getFillRelayDelegatePda(relayHashUint8Array, repaymentChainId, repaymentAddress, program.programId).pda;

          // Delegate fill delegate PDA to pull relayer tokens.
        const approveIx = await createApproveCheckedInstruction(
            relayerTokenAccount,
            outputToken,
            delegate,
            signer.publicKey,
            BigInt(relayData.outputAmount.toString()),
            tokenDecimals,
            undefined,
            TOKEN_PROGRAM_ID
        );

        const fillDataValues: FillDataValues = [Array.from(relayHashUint8Array), relayData, repaymentChainId, repaymentAddress];

        const fillAccounts = {
            state: statePda,
            signer: signer.publicKey,
            delegate,
            instructionParams: program.programId,
            mint: outputToken,
            relayerTokenAccount: relayerTokenAccount,
            recipientTokenAccount: recipientTokenAccount,
            fillStatus: fillStatusPda,
            tokenProgram: TOKEN_PROGRAM_ID,
            associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
            systemProgram: SystemProgram.programId,
            programId: programId,
            program: program.programId,
        };

        const fillIx = await program.methods
            .fillRelay(...fillDataValues)
            .accounts(fillAccounts)
            .instruction();
        
        //const fillTx = new Transaction().add(createTokenAccountsIx, approveIx, fillIx);
        const fillTx = new Transaction().add(approveIx, fillIx);

        if(sendRelays == true) { 
            try { 
                logMessage(`${depositId}: Submitting relay transaction`);
                const tx = await sendAndConfirmTransaction(provider.connection, fillTx, [signer]);
                logMessage(`${depositId}: Relay transaction signature: ${tx}`, "green");
                if(tx) { 
                    logMessage(`${depositId}: 🚀 Relay transaction successful`, "greenbold");
                } else {
                    logMessage(`${depositId}: 💀 Relay transaction failed (alt)`, "red");
                }
            } catch (err) {
                const errorDetails = err + '';
                if(errorDetails.indexOf(":6004}") != -1) { 
                    logMessage(`${depositId}: 💀 Relay transaction failed: already filled`, "red");
                } else {
                    logMessage(`${depositId}: 💀 Relay transaction failed:`, "red");
                    console.log(err);
                }
            }
        } else {
            logMessage(`${depositId}: SendRelays is disabled, simulation complete`, "green");
        }
    }


    
}


async function findPdasToClose() { 
    let sql = `
        SELECT *
        FROM relays
        WHERE (relayer = '0xa61164440a720bee95f3579404c415b7fbcda4379eead6fd229df27b3bf706b4' OR relayer = '0x394311a6aaa0d8e3411d8b62de4578d41322d1bd') 
        AND destinationChainId = 34268394551451
        AND pda IS NOT NULL
        AND closePdaSignature IS NULL
        AND fillDeadline < UNIX_TIMESTAMP(NOW());
    `; 
    const [rows, fields] = await dbConnection.query(sql);
    const rowDataPackets = rows as RowDataPacket[];
    for(const relay of rowDataPackets) { 
        const seed = new BN('0');
        const [statePda] = PublicKey.findProgramAddressSync(
            [Buffer.from("state"), seed.toArrayLike(Buffer, "le", 8)],
            programId
        );

        const state = await program.account.state.fetch(statePda);
        const chainId = new BN(state.chainId);

        const accountInfo = await provider.connection.getAccountInfo(new PublicKey(relay.pda));
        if (!accountInfo) {
            logMessage(`${relay.depositId} Fill Status PDA is already closed or does not exist.`);
            return;
        }

        logMessage("");
        logMessage(`${relay.depositId}: Preparing closeFillPda instruction:`);
        console.table([
            { Property: "State PDA", Value: statePda.toString() },
            { Property: "Fill Status PDA", Value: new PublicKey(relay.pda).toString() }
        ]);

        const closeIx = await (program.methods.closeFillPda() as any)
            .accounts({
                state: statePda,
                signer: wallet.publicKey,
                fillStatus: new PublicKey(relay.pda),
                systemProgram: SystemProgram.programId,
            })
            .instruction();

        const closeTx = new Transaction().add(closeIx);

        const signer = wallet;

        const tx = await sendAndConfirmTransaction(provider.connection, closeTx, [signer]);

        logMessage(`${relay.depositId}: CloseFillPda transaction signature: ${tx}`, "purple");

    }

}


async function blockCounter(depositId: string, chainId: number, depositBlockNumber: number, targetBlock: number) {
    const rpcUrl = mainConfig.websocketRpcs[`${chainId}`];
    const provider = new ethers.providers.WebSocketProvider(rpcUrl);

    // how many blocks are between the deposit block and the target block?
    const blocksToWait = targetBlock - depositBlockNumber;
  
    return new Promise<void>((resolve) => {
      provider.on("block", (blockNumber) => {

        const blocksSoFar = blockNumber - depositBlockNumber;
        logMessage(`${depositId}: Block Counter: ${blockNumber} (${blocksSoFar}/${blocksToWait})`);
        if (blockNumber >= targetBlock) {
          logMessage(`${depositId}: Reached target block ${targetBlock}`);
          resolve();
          provider.destroy(); // closes WebSocket in ethers v5
        }
      });
    });
}

async function runQuorumCheck(depositId : string, deposit: any) { 
    logMessage(`${depositId}: Running quorum check:`);

    let rpcUrl = mainConfig.websocketRpcs[`${deposit.originChainId}`];
    let provider = new ethers.providers.WebSocketProvider(rpcUrl);
    
    // get the deposit receipt
    const depositReceipt = await provider.getTransactionReceipt(deposit.transactionHash);
    logMessage(`${depositId}: Transaction receipt ${deposit.transactionHash}`);
    // loop through logs to find the deposit topic
    let depositIdFound = false;
    for(const log of depositReceipt.logs) { 
        if(log.topics.includes(mainConfig.topics.depositTopic)) { 

            const receiptDestinationChainId = Number(hexToDecimal(log.topics[1]));
            const receiptDepositId = ethers.BigNumber.from(log.topics[2]);
            const receiptDepositor = hexToBytes32(log.topics[3]);
            
            if(Number(depositId) == Number(receiptDepositId)) { 
                depositIdFound = true;

                // create the relay hash from the receipt
                const receiptDeposit = decodeEvmDeposit(log.data);
                const receiptDepositForHash = { 
                    depositor : receiptDepositor,
                    recipient : receiptDeposit[7],
                    exclusiveRelayer : receiptDeposit[8],
                    inputToken : receiptDeposit[0],
                    outputToken : receiptDeposit[1],
                    inputAmount : receiptDeposit[2],
                    outputAmount : receiptDeposit[3],
                    originChainId : deposit.originChainId,
                    depositId : receiptDepositId,
                    fillDeadline : receiptDeposit[5],
                    exclusivityDeadline : receiptDeposit[6],
                    message: receiptDeposit[9]
                }
                //console.log(receiptDepositForHash);

                // get the relay hash from the receipt data
                const receiptRelayHash = getEvmRelayHash(receiptDepositForHash, receiptDestinationChainId);
                logMessage(`${depositId}: Receipt Relay Hash: ${receiptRelayHash}`);

                // create the relay hash from the deposit data: 
                const depositForHash = { 
                    depositor : hexToBytes32(deposit.depositor),
                    recipient : hexToBytes32(deposit.recipient),
                    exclusiveRelayer : hexToBytes32(deposit.exclusiveRelayer),
                    inputToken : hexToBytes32(deposit.inputToken),
                    outputToken : hexToBytes32(deposit.outputToken),
                    inputAmount : deposit.inputAmount,
                    outputAmount : deposit.outputAmount,
                    originChainId : deposit.originChainId,
                    depositId : depositId,
                    fillDeadline : deposit.fillDeadline,
                    exclusivityDeadline : deposit.exclusivityDeadline,
                    message: deposit.message
                }
                //console.log(depositForHash);

                const depositRelayHash = getEvmRelayHash(depositForHash, Number(deposit.destinationChainId.hex.toString()));
                logMessage(`${depositId}: Deposit Relay Hash: ${depositRelayHash}`);
                if(depositRelayHash == receiptRelayHash) { 
                    logMessage(`${depositId}: ✅ Relay hashes match! Continue`);
                    depositIdFound = true;
                    return true;
                } else { 
                    logMessage(`${depositId}: ❌ Relay hashes do not match! Abort!`, "red");
                    return false;
                }
                break;
            }
            
        }
    }
    
}



async function loadWallet() { 
    const seed = await bip39.mnemonicToSeed(mnemonic);
    const path = `m/44'/501'/0'/0'`;
    const derivedSeed = ed25519.derivePath(path, seed.toString("hex")).key;
    wallet = Keypair.fromSeed(derivedSeed);
    const hex = Buffer.from(wallet.publicKey.toBytes()).toString("hex");
    relayerHexAddress = `0x${hex}`;
    logMessage(`✅ Wallet svm address: ${wallet.publicKey.toBase58()}`);
    logMessage(`✅ Wallet hex address: ${relayerHexAddress}`);
    provider = new AnchorProvider(connection, {
        publicKey: wallet.publicKey,
        signTransaction: tx => wallet.signTransaction(tx),
        signAllTransactions: txs => txs.map(t => wallet.signTransaction(t)),
    }, {});
    programId = new web3.PublicKey(SvmSpokeIdl.address);
    program = new Program(SvmSpokeIdl, {connection, provider});
    logMessage(`✅ Anchor provider created: ${SvmSpokeIdl.address}`);
}

function evmToSolanaPK(evmAddress : string) {
    const hex = evmAddress.replace(/^0x/, "").toLowerCase();
    if (hex.length !== 40) throw new Error("Invalid EVM address");
  
    const buf = Buffer.alloc(32);
    Buffer.from(hex, "hex").copy(buf, 12); // right-align, zero-pad left 12 bytes
    return new PublicKey(buf);
}

function hexToSolanaPK(hexAddress : string) {
    const hex = hexAddress.replace(/^0x/, "").toLowerCase();
  
    const buf = Buffer.alloc(32);
    Buffer.from(hex, "hex").copy(buf); // right-align, zero-pad left 12 bytes
    return new PublicKey(buf);
}

async function updateUsdcBalance() { 
    await updateTokenBalance("USDC", USDC_MINT, wallet.publicKey.toBase58());
}

async function updateTokenBalance(tokenName: string, tokenAddress: string, svmWalletAddress: string, displayBalance: boolean = true) { 
    // 3. Get Associated Token Account (ATA) for USDC
    let TOKEN_ADDRESS = new PublicKey(tokenAddress);
    const MY_ADDRESS = new PublicKey(svmWalletAddress);
    const ata = await getAssociatedTokenAddress(TOKEN_ADDRESS, MY_ADDRESS);
    const accountInfo = await getAccount(connection, ata);
    const balance = Number(accountInfo.amount);
    const oldBalance = await redisClient.get(`${svmWalletAddress}_${solanaChainId}_${tokenName}`);
    await redisClient.set(`${svmWalletAddress}_${solanaChainId}_${tokenName}`, balance);
    if(displayBalance && Number(oldBalance) != Number(balance)) { 
        logMessage("");
        logMessage(`${svmWalletAddress} balance: ${balance/1e6} ${tokenName}`);
    }
}

function findOriginToken(chainId: Number, tokenAddress: string) {
    for (const key in tokenConfig) {
        if (tokenConfig.hasOwnProperty(key)) {
            const addresses = tokenConfig[key].addresses;
            if (addresses?.[chainId.toString()]?.toLowerCase() === tokenAddress.toLowerCase()) {
                return key;
            }
        }
    }
    return '';
}

function findDestinationToken(chainId : Number, asset : string) { 
    return tokenConfig[asset].addresses[chainId.toString()];
}

export async function connectMysql(): Promise<void> {
	// Initialize the database connection
	dbConnection = await mysql.createPool(connectionData);
}

function initializeRedis() { 
    // Handle connection and error events
    redisClient.on('connect', () => {
        logMessage('🧠 Redis ready');
    });
    
    redisClient.on('error', (err) => {
        logMessage(`Redis error: ${err}`);
    });
}

async function updateBlacklist() { 
	const blacklistRaw = fs.readFileSync("../relayer/cache/blacklist.txt", 'utf-8');
	const blacklist = blacklistRaw.split('\n');
	blacklistLowercase = blacklist.map(address => address.toLowerCase());
	logMessage("Blacklist updated", "yellow");
}

function customSleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
}
function loadEncryptedEnv() {
	const passphrase = process.env.ENV_PASSPHRASE;
	if (!passphrase) {
	  throw new Error("ENV_PASSPHRASE is not set");
	}
  
	// Decrypt .env.gpg in memory
	const decrypted = execSync(
	  `gpg --quiet --batch --yes --decrypt --passphrase=${passphrase} ../relayer/.env.gpg`,
	  { encoding: "utf8" }
	);
  
	// Parse and load into process.env
	const envVars = dotenv.parse(decrypted);
	for (const k in envVars) {
	  process.env[k] = envVars[k];
	}
}



/* 
const sampleDeposit = {
    depositId: { type: 'BigNumber', hex: '0x011055' },
    humanDate: '2025-08-30 12:16:15',
    timestamp: 1756556175,
    transactionHash: '0xc138404f54b3322e6f242a7fcda88b94e7ea5d2d9cbdb7abf21c6c5031ba713a',
    depositKey: '69717_USDC_56_34268394551451_501000000000000000',
    logIndex: 1633,
    blockNumber: 59410433,
    originChainId: 56,
    destinationChainId: { type: 'BigNumber', hex: '0x1f2abb7bf89b' },
    depositor: '0xbe75079fd259a82054caab2ce007cd0c20b177a8',
    recipient: '0x8fe31c92135d733c826f5d8e9fc4ff8710ef4b382335e1b965935539a32e248b',
    inputToken: '0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d',
    outputToken: '0xc6fa7af3bedbad3a3d65f36aabc97431b1bbe4c2d2f6e0e47ca60203452f5d61',
    inputAmount: '501000000000000000',
    outputAmount: '499822',
    quoteTimestamp: 1756556015,
    fillDeadline: 1756567838,
    exclusivityDeadline: 0,
    exclusiveRelayer: '0x0000000000000000000000000000000000000000',
    message: '0x',
    tokenName: 'USDC',
    outputTokenName: 'USDC',
    straddl: 0,
    integrator: '1dc0de007f'
  }
  */
  setTimeout(() => {
    findPdasToClose();
  }, 1000);
  