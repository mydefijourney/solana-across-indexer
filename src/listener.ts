import fs from 'fs';
import Redis from 'ioredis';
import axios from 'axios';
import dotenv from 'dotenv';
import mysql, { Connection } from 'mysql2/promise';
import { RowDataPacket, OkPacket  } from 'mysql2';
import { Connection, PublicKey, clusterApiUrl } from "@solana/web3.js";
import { getAccount, getAssociatedTokenAddress } from "@solana/spl-token";
import { isAddress} from "@solana/kit";
import { BN, BorshEventCoder, Idl } from "@coral-xyz/anchor";
import bs58 from "bs58";
import { Buffer } from "buffer";
import { ethers } from 'ethers';
import { logMessage, hexToAddress, hexToDecimal, readU64LE, readU64BE, readU32LE, decodeDepositEvent, decodeFillRelayEvent, decodeRefundEvent } from './functions';
import { WebSocketServer } from "ws";

import * as across from "@across-protocol/sdk";


const relayerStartTime = new Date();
logMessage("Starting Solana event scraper", "greenbold");
logMessage("\n.....................:c.........................................................\n..................;dOXXkc.........................................:c:ccccc;.....\n.................,0NNNNNXc.......................................,KNNNNNNN0,....\n.................cXNNNNNO'.......................................cKNNNNNNN0'....\n..................;d0Oocodc.................................'d0KKXNNNNNNNN0'....\n..........................cdo::'...........................lKNNNNNNNNNNNNN0'....\n............................cKN0;..........................;:;oKNNNNNNNNNN0'....\n.....................lxO0Ox;.lXN0l'...........................,0NNNNNNNNNN0'....\n...................;0NXXXNNXl'xNNKko;.........................,0NNNNNNNNNN0'....\n...................d00000000O,,0NKl;odc'......................,0NNNNNNNNNN0'....\n...................'dxxxxxxx;.c0NNd..,OK00l...................,0NNNNNNNNNN0'....\n....................cKNNNNXOdONXOc...cKNN0xo,............:odddkXNNNNNNNNNN0'....\n......................:lldkKNXk:....cKN0x;.'..........:kKNNNNNNNNNNNNNNNNN0'....\n.....................:oxx0NN0l'....cKN0;..............ONXNNNN0xdddddxKNNNN0'....\n....................dNNNNNNNK0OOOkOKNK:...............kNXNNNNk;,,,,,:ONNNN0'....\n...................'0NXNNNNXOdddxxxkx,................xNNNNNNXXXXXXXXNNNNN0'....\n...................,0NXNNNNX:..........................dXNNNNNNNNNNNNNNNNN0'....\n...................,0NNNNNNX:.........................,kXNNNNNNNNNNNNNNNXN0'....\n...................,0NNNNNNX:........................,ONNNNNNNNNNNNNXNNNNN0'....\n...................,0NNNNNNX:......................,oONNNN0o::c::ckNNNNNNN0'....\n...................,0NNNNXNXc......................xNXNNNNKdllllloOXNNNNNN0'....\n...................:KNNNNXNNO;....................:ONXNNNNNNNNNNNNNNNNNNNN0'....\n...................xNXNKOKNNNKo................,d0NNNNNNNNNXNNNNNXNNNNNNNN0'....\n..................;KNNNd.,ONNNNO;.............'ONNNNNNNNNNNNNNNNNNNNNNNNNN0'....\n..................dNNNK:...dXNXNK;............'ONNNNNNNNNNNNNNNNNNNNNNNNXN0'....\n.................cKNXNk.....lXNNNO'...........'ONXNNNNNNNNNNNNX0OOOOOOKXNN0'....\n...............'xXNNNXc......dNNNNd...........'ONNNNNNNNNNNXNN0c,,,,,,dXNN0'....\n..............oKNNNXO;.......'ONNNXl...........lkXNXNNNNNNNNNNXK00000KKNNN0'....\n............cONNNN0l..........;KNXN0;...........:0NNNNNNNNNNNNNNNNNNXNNNNN0'....\n...........xNNXNKd'............lXNNNk........'kKKNNNNNNNNNNNNNNNNNNNNNNNNN0,....\n...........xNNXx,..;;....lkKx,'ckXNNK;..','..'0XxcckNNNNNNNNNNNNNNNNNNNNNN0,....\n........c;..,;'...'ll,...:ccc:l:.:oo;..'cll;..ll,..'odddddddddddddddddddddl.....\n");

// get the main configs
dotenv.config();


const mainConfigRaw = fs.readFileSync("../relayer/configurations/main.json", 'utf-8');
const mainConfig = JSON.parse(mainConfigRaw);
logMessage("✅ Main config loaded");

const tokenConfigRaw = fs.readFileSync("../relayer/configurations/tokens.json", 'utf-8');
const tokenConfig = JSON.parse(tokenConfigRaw);
//console.log(tokenConfigRaw);
logMessage("✅ Token config loaded");

const connectionData = {
	host: process.env.MYSQL_HOST,
	port: Number(process.env.MYSQL_PORT),
	user: process.env.MYSQL_USER,
	password: process.env.MYSQL_PASS,
	database: process.env.MYSQL_DB,
	ssl: {
		ca: fs.readFileSync(process.env.MYSQL_SSL as string),
	},
};
export default connectionData;
let dbConnection: Connection;
connectMysql();


// initialize redis to cache gas prices
const redisClient = Redis.createClient();
const redisExp = 14400; // expire keys after 4h
initializeRedis();

const runMode : string = process.env.RUNMODE || "live";
logMessage(`Run mode: ${runMode}`, "greenbold");

const clients: Set<WebSocket> = new Set();

if(process.env.RUNMODE != "test") { 
  const wss = new WebSocketServer({ port: 3333, host: "0.0.0.0" });
  logMessage("✅ Websocket server started on port 3333");
  wss.on("connection", (ws, req) => {
    const ip = req.socket.remoteAddress;
    clients.add(ws);
    logMessage(`Client connected from ${ip}`, "yellow");
    //ws.send("Hello from server");
    ws.on("close", () => {
      clients.delete(ws);
    });
  });
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

// ================= CONFIG =================
const RPC_URL = process.env.SOLANA_RPC_URL || clusterApiUrl("mainnet-beta");
const PROGRAM_ID = new PublicKey("DLv3NggMiSaef97YCkew5xKUHDh13tVGZ7tydt3ZeAru");
const IDL_ADDRESS = new PublicKey("7wBtxUB8rGbgAuiURishKddxvreFTVqnxw1uhXhmuXnk");

const connection = new Connection(RPC_URL, "confirmed");
logMessage("🚀 Watching for events from " + PROGRAM_ID.toBase58());


updateMyBalance();
setInterval(updateMyBalance, 60000);




// ================= WATCHER =================
connection.onLogs(PROGRAM_ID, async (logInfo) => {
  const signature = logInfo.signature;
  await processTransaction(signature);
}, "confirmed");


async function processTransaction(signature: string, retries: number = 0) { 


  logMessage("");
  logMessage(`Processing ${signature}`);
  const existsInRedis = await redisClient.get(`solana_event_${signature}`);
  if(existsInRedis && runMode == "live") { 
    logMessage(`Event ${signature} locked, skipping`, "gray");
    return;
  }

  try {
    const tx = await connection.getTransaction(signature, {
      commitment: "confirmed",
      maxSupportedTransactionVersion: 0,
    });
    if (!tx) { 
      logMessage(`Transaction ${signature} not found, trying again in 1s`, "red");
      customSleep(1000);
      if(retries < 5) { 
        processTransaction(signature, retries + 1);
      }
      return;
    }

    const innerInstructions = tx.meta?.innerInstructions || [];
    const compiledInstructions = tx.transaction?.message?.compiledInstructions || [];
    const staticAccountKeys = tx.transaction?.message?.staticAccountKeys || [];

    //console.log(tx);
    //console.log(compiledInstructions);
    //console.log(staticAccountKeys);

    await redisClient.set(`solana_event_${signature}`, "locked", "EX", 60);

    // what type of event is this? 
    let eventType = "unknown";
    if(tx.meta?.logMessages?.includes("Program log: Instruction: Deposit")) { 
      eventType = "deposit";
    } else if(tx.meta?.logMessages?.includes("Program log: Instruction: FillRelay")) { 
      eventType = "relay";
    } else if(tx.meta?.logMessages?.includes("Program log: Instruction: ExecuteRelayerRefundLeaf")) { 
      eventType = "refund";
    } else if(tx.meta?.logMessages?.includes("Program log: Instruction: CloseFillPda")) { 
      eventType = "closeFillPda";
    } else if(tx.meta?.logMessages?.includes("Program log: Instruction: RelayRootBundle")) { 
      eventType = "relayRootBundle";
    } else if(tx.meta?.logMessages?.includes("Program log: Instruction: HandleReceiveMessage")) { 
      eventType = "handleReceiveMessage";
    } else if(tx.meta?.logMessages?.includes("Program log: Instruction: ReceiveMessage")) { 
      eventType = "receiveMessage";
    } else if(tx.meta?.logMessages?.includes("Program log: Instruction: InitializeInstructionParams")) { 
      eventType = "initializeInstructionParams";
    } else if(tx.meta?.logMessages?.includes("Program log: Instruction: WriteInstructionParamsFragment")) { 
      eventType = "writeInstructionParamsFragment";
    } 

    //logMessage(`Event Type:: ${eventType}`);




    
    if(eventType == "deposit" || eventType == "relay" || eventType == "refund") { 
      for (const inner of innerInstructions) {
        //console.log(inner);
        if (!inner.instructions) continue;

        for (const instr of inner.instructions) {
          //console.log(instr);
          if(eventType == "deposit" && tx.transaction.message.accountKeys) { 
            // this is probably a deposit
            const programIdPubKey = tx.transaction.message.accountKeys[instr.programIdIndex];
            if (!programIdPubKey.equals(PROGRAM_ID)) continue;

            let eventTypeLine = tx.meta?.logMessages?.[instr.programIdIndex+1];

            
            //console.log("Block Number: ", tx.slot);
            //console.log("Block Time: ", tx.blockTime);
            //console.log("humanDate: ", formatMySQLDate(new Date(tx.blockTime * 1000)));
            //console.log("logIndex: ", instr.programIdIndex);

            try {
              const event = decodeDepositEvent(instr.data);

              logMessage("===== Deposit Event =====");
              logMessage(`Event Signature: ${signature}`);
              // console.log(event);
              // logMessage("=========================");

              // prepare insert
              const dataForinsert = { 
                depositId: event.depositId,
                humanDate: formatMySQLDate(new Date(tx.blockTime * 1000)),
                timestamp: tx.blockTime,
                depositKey: event.depositKey,
                transactionHash: signature,
                logIndex: instr.programIdIndex,
                blockNumber: tx.slot,
                originChainId: event.originChainId,
                destinationChainId: event.destinationChainId,
                depositor: event.depositor,
                recipient: event.recipient,
                inputToken: event.inputToken,
                outputToken: event.outputToken,
                inputAmount: event.inputAmount,
                outputAmount: event.outputAmount,
                quoteTimestamp: event.quoteTimestamp,
                fillDeadline: event.fillDeadline,
                exclusivityDeadline: event.exclusivityDeadline,
                exclusiveRelayer: event.exclusiveRelayer,
                message: event.message,
                tokenName: event.tokenName,
                outputTokenName: event.outputTokenName,
              }

              wssBroadcast({
                type: "DEPOSIT",
                data: dataForinsert
              });

              let depositStatement = '';
                  
              let tokenDecimals = Math.pow(10,tokenConfig[`${event.tokenName}`].decimals);
              let destTokenDecimals = tokenDecimals; 
              // specific to BNB chain
              if(event.outputTokenName == 'USDC' && event.destinationChainId == 56) {
                destTokenDecimals = 18;
              }
              let destinationChainName = mainConfig.chainNames[`${event.destinationChainId}`];
              depositStatement = `Deposit ${event.depositId}: ${event.inputAmount/tokenDecimals} ${event.tokenName} from Solana to ${Number(event.outputAmount)/Number(destTokenDecimals).toFixed(6)} ${event.outputTokenName} on ${destinationChainName}`;


              // insert into the database
              const [result] = await dbConnection.query('INSERT INTO deposits SET ?', dataForinsert);
              const insertId = result.insertId;
              logMessage(`${depositStatement}`, "blue");



            } catch (err) {
              console.error("Error decoding Deposit event:", err);
            }
          } else if(eventType == "relay" && tx.transaction.message.staticAccountKeys) { 
            // this is probably a relay
            const programIdPubKey = tx.transaction.message.staticAccountKeys[instr.programIdIndex];
            if (!programIdPubKey.equals(PROGRAM_ID)) continue;

            let eventTypeLine = tx.meta?.logMessages?.[instr.programIdIndex+1];

            //console.log("===== Non-Deposit Event =====");
            //console.log(`===== ${eventTypeLine} =====`);
            //console.log("Event Signature: ", signature);
            //console.log("Block Number: ", tx.slot);
            //console.log("Block Time: ", tx.blockTime);
            //console.log("humanDate: ", formatMySQLDate(new Date(tx.blockTime * 1000)));
            //console.log("logIndex: ", instr.programIdIndex);

            // find the accompanyting PDA 
            let thisPda = '';
            for(const instr of compiledInstructions) { 
              let programId = staticAccountKeys[instr.programIdIndex];
              if(programId.toBase58().toString() == PROGRAM_ID) { 
                  // programId match
                  thisPda = staticAccountKeys[instr.accountKeyIndexes[7]].toBase58();
                  //logMessage(`PDA created: ${thisPda}`);
              } 
            }

            try { 

              if(tx.meta?.logMessages.includes("Program log: Instruction: FillRelay")) { 
                // this is probably a fill relay
                const event = decodeFillRelayEvent(instr.data);
                logMessage("===== FillRelay Event =====");
                logMessage(`Event Signature: ${signature}`);
                //logMessage(`PDA created: ${thisPda}`);
                // console.log(event);
                //logMessage("=========================");

                // before we can insert, we need to find the matching depositId
                const matchingDeposit = await findDeposit('', event.depositKey);
                if(matchingDeposit.length > 0) { 
                  //console.log("Matching deposit found");
                  //console.log(matchingDeposit);
                  
                  const pricesFilePath = '../relayer/configurations/prices.json';
                  const rawPriceJson = fs.readFileSync(pricesFilePath, 'utf-8');
                  let pricesJsonData = JSON.parse(rawPriceJson);

                  // prepare insert
                  const dataForinsert = { 
                    depositId: event.depositId,
                    humanDate: formatMySQLDate(new Date(tx.blockTime * 1000)),
                    timestamp: tx.blockTime,
                    depositKey: event.depositKey,
                    transactionHash: signature,
                    logIndex: instr.programIdIndex,
                    blockNumber: tx.slot,
                    originChainId: event.originChainId,
                    destinationChainId: event.destinationChainId,
                    repaymentChainId: event.repaymentChainId,
                    relayer: event.relayer,
                    repaymentAddress: event.relayer,
                    depositor: event.depositor,
                    recipient: event.recipient,
                    inputToken: event.inputToken,
                    outputToken: event.outputToken,
                    inputAmount: event.inputAmount,
                    outputAmount: event.outputAmount,
                    fillDeadline: event.fillDeadline,
                    exclusivityDeadline: event.exclusivityDeadline,
                    exclusiveRelayer: event.exclusiveRelayer,
                    message: matchingDeposit[0].message,
                    messageHash: event.messageHash,
                    inputTokenName: event.tokenName,
                    tokenName: event.outputTokenName,
                    realizedLpFeePct: 0,
                    depositHash: matchingDeposit[0].transactionHash,
                    depositBlockNumber: matchingDeposit[0].blockNumber,
                    depositTimestamp: matchingDeposit[0].timestamp,
                    expectedRefund: event.inputAmount,
                    txFee: (tx.meta?.fee * 1e9),
                    howManyFills: 1,
                    gasUsed: 0,
                    effectiveGasPrice: 0,
                    gasBaseFee: 0,
                    nativeTokenPrice: pricesJsonData['SOL'].toFixed(2),
                    inputTokenPrice: pricesJsonData[event.tokenName].toFixed(2),
                    tokenPrice: pricesJsonData[event.outputTokenName].toFixed(2),
                    timeToFill: Number(tx.blockTime) - matchingDeposit[0].timestamp,
                    integrator: matchingDeposit[0].integrator,
                    pda: thisPda,
                  };

                  let depositStatement = '';
                  
                  let tokenDecimals = Math.pow(10,tokenConfig[`${event.tokenName}`].decimals);
                  let destTokenDecimals = tokenDecimals; 
                  // specific to BNB chain
                  if(event.originChainId == 56) {
                    tokenDecimals = 1e18;
                  }
                  if(event.destinationChainId == 56) {
                    destTokenDecimals = 1e18;
                  }
                  let originChainName = mainConfig.chainNames[`${event.originChainId}`];
                  depositStatement = `Relay ${event.depositId}: ${Number(event.inputAmount)/Number(tokenDecimals)} ${event.tokenName} from ${originChainName} to ${(event.outputAmount/destTokenDecimals).toFixed(6)} ${event.outputTokenName} on Solana filled by ${event.relayer}`;
                  let depositStatement2 = `Relay ${event.depositId}: PDA ${thisPda}`;

                  // insert into the database
                  const [result] = await dbConnection.query('INSERT INTO relays SET ?', dataForinsert);
                  const insertId = result.insertId;
                  logMessage(`${depositStatement}`, "yellow");
                  logMessage(`${depositStatement2}`, "yellow");

                  wssBroadcast({
                    type: "RELAY",
                    data: dataForinsert
                  });

                } else { 
                  console.log("No matching deposit found");
                }


              }

              //const event = decodeFillRelayEvent(instr.data);
            } catch (err) { 
              console.error("Error decoding FillRelay event:", err);
            }
          } else if(eventType == "refund" && tx.transaction.message.staticAccountKeys) { 
            // this is probably a relay
            const programIdPubKey = tx.transaction.message.staticAccountKeys[instr.programIdIndex];
            //if (!programIdPubKey.equals(PROGRAM_ID)) continue;

            let eventTypeLine = tx.meta?.logMessages?.[instr.programIdIndex+1];

            //console.log("===== Non-Deposit Event =====");
            //console.log(`===== ${eventTypeLine} =====`);
            //console.log("Event Signature: ", signature);
            //console.log("Block Number: ", tx.slot);
            //console.log("Block Time: ", tx.blockTime);
            //console.log("humanDate: ", formatMySQLDate(new Date(tx.blockTime * 1000)));
            //console.log("logIndex: ", instr.programIdIndex);

            try { 
              const instructionLength = instr.data.length;
              if(tx.meta?.logMessages.includes("Program log: Instruction: ExecuteRelayerRefundLeaf") && instructionLength > 40) { 
                // this is probably a refund
                const event = decodeRefundEvent(instr.data);
                if(!event) {
                  logMessage("Refund event item, but no refund event found");
                  continue;
                }
                logMessage("===== Refund Event =====");
                logMessage(`Event Signature: ${signature}`);
                //console.log(event);
                //logMessage("=========================");
                  
                const pricesFilePath = '../relayer/configurations/prices.json';
                const rawPriceJson = fs.readFileSync(pricesFilePath, 'utf-8');
                let pricesJsonData = JSON.parse(rawPriceJson);

                // loop through the refundAmounts to insert for each relayer
                for(let i = 0; i < event.refundAmounts.length; i++) { 


                  // prepare insert
                  const dataForinsert = { 
                    humanDate: formatMySQLDate(new Date(tx.blockTime * 1000)),
                    timestamp: tx.blockTime,
                    transactionHash: signature,
                    logIndex: instr.programIdIndex,
                    blockNumber: tx.slot,
                    chainId: event.refundChainId,
                    rootBundleId: event.rootBundleId,
                    leafId: event.leafId,
                    relayer: event.refundAddresses[i],
                    tokenAddress: event.l2TokenAddress,
                    refundAmount: event.refundAmounts[i],
                    tokenName: event.tokenName,
                    tokenPrice: pricesJsonData[event.tokenName].toFixed(2)
                  };

                  // insert into the database
                  const [result] = await dbConnection.query('INSERT INTO refunds SET ?', dataForinsert);
                  const insertId = result.insertId;
                  // todo: fix token decilmsls
                  logMessage(`Refund of ${Number((event.refundAmounts[i])/1e6)} ${event.tokenName} for ${event.refundAddresses[i]} inserted into the database`, "purple");

                  wssBroadcast({
                    type: "REFUND",
                    data: dataForinsert
                  });

                }


              }

            } catch (err) { 
              console.error("Error decoding Refund event:", err);
            }
          }
        }
      }
    } else if(eventType != 'unknown') { 
      logMessage(`===== ${eventType} Event =====`);
      logMessage(`Event Signature: ${signature}`);
    } else { 
      logMessage(`===== Unknown Event =====`);
      logMessage(`Event Signature: ${signature}`);
      console.log(tx.meta?.logMessages);
    }  


    // check for closeFillPda
    if(eventType == "closeFillPda" && compiledInstructions.length > 0) { 
      for(const instr of compiledInstructions) { 

        if(instr.accountKeyIndexes.length == 3) { 
          const signer = staticAccountKeys[instr.accountKeyIndexes[0]];
          const state = staticAccountKeys[instr.accountKeyIndexes[1]];
          const fillStatus = staticAccountKeys[instr.accountKeyIndexes[2]];

          const thisPda = fillStatus.toBase58();
          // find the matching deposit
          let thisSql = `SELECT * FROM relays WHERE pda = '${thisPda}'`;
          const [rows, fields] = await dbConnection.query(thisSql);
          const rowDataPackets = rows as RowDataPacket[];
          if(rowDataPackets.length > 0) { 
            let dataForUpdate = { 
              id: rowDataPackets[0].id,
              closePdaSignature: signature
            };
            await dbConnection.query('UPDATE relays SET ? WHERE pda = ?', [dataForUpdate, thisPda]);
            logMessage("===== CloseFillPda Event =====");
            logMessage(`Event Signature: ${signature}`);
            logMessage(`Relay   ${rowDataPackets[0].depositId} PDA closed by ${signer.toBase58()}`, "green");
          } else { 
            logMessage(`No matching deposit found to match PDA ${thisPda}`, "orange");
          }

        }


      }
    }
  } catch (err) {
    console.error("Error fetching transaction:", err);
  }
}



function formatMySQLDate(date: Date): string {
  const year = date.getFullYear();
  const month = ('0' + (date.getMonth() + 1)).slice(-2);
  const day = ('0' + date.getDate()).slice(-2);
  const hours = ('0' + date.getHours()).slice(-2);
  const minutes = ('0' + date.getMinutes()).slice(-2);
  const seconds = ('0' + date.getSeconds()).slice(-2);
  
  return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
}


function customSleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}


async function findDeposit(transactionHash: string, depositKey: string) {
  try {
    // Check if entry exists

	if(transactionHash != '') { 
		const [rows, fields] = await dbConnection.query('SELECT * FROM deposits WHERE transactionHash = ? AND depositKey = ? ORDER BY id ASC', [transactionHash, depositKey]);
		const rowDataPackets = rows as RowDataPacket[];
		return rowDataPackets;
	} else { 
		const [rows, fields] = await dbConnection.query('SELECT * FROM deposits WHERE depositKey = ?', depositKey);
		const rowDataPackets = rows as RowDataPacket[];
		return rowDataPackets;
	}

	
  } catch (error) {
    throw error;
  }
}

// Helper to broadcast messages
function wssBroadcast(message: object) {
  const msgString = JSON.stringify(message);
  for (const client of clients) {
    client.send(msgString);
  }
}



async function main2() { 


  //const base58Data = '6kXLCq19rCrtQ6uDU4UZsvPqH2poHZEcauCD2j9WxjwEWXSEq5oixhQqzrxf7JgvRj2Au81C6GY2Zt3YMXajNGCcfEWPdkAhkLG7KqSbeaWGqjz7jG1TqXg64LYAm6zUvVFDckzpoRJLJKEp2Q1XYit9E9SkmXvyYEnZfPiyd617gaAZ3XAa56NJDH8hFTjR7j6JJYc8hGttFopS2KcFutR3NdFDGcRiW6vtcCgfUQvQ5GCz8LULjEejaXi67mPWVHgiQW7mSyexup9EtT5q33g34vqTSq3H4cXjDVzyCJaHn6EkV9LRe4LeA55WzP53ks8jq5B3EDLfKz44q7xDjJsEtbxmRG3WpPjPeu93irQtqioyy5Yj';
  //const base58Data = '6kXLCq19rCrtQ6uDU4UZsvPqH2poHZEcauCD2j9WxjwEWXSEq5oixhQqzrxf7JgvRj2Au81C6GY2Zt3YMXaVE8T8WSHZiY1z3zFqSVuTaCcuWo8NoKUkK3fUX7R6A89Q9mkVG5XL1vPjvguoV99vi3XpsCnypF2KkWRNhMFJYKLq85r31S76U25Wfk11BxLjBHTV6XEuA8YQWBQDj3nPsX9J65J2oxx1U64qqZWLwzQPLCw4d8o8geWZo3XVjTHuepFyEs4Wdbcyyd2WPcebBnUa1pjAkhGB4m73e2JHY6ANF6AfeSq5aRzf8Edgkd31wPUZmC8Uf2gExuyraJQ5LYxUsABQd4gecqyiyytnZ8LLc7AgbikX';
  //const event = decodeDepositEvent(base58Data);
 // console.log("event", event);

  //const base58Data = '9TsSUqX1Euf1kfjPg6QzPHF6EcEiYpP1oKAJqkDDEKCAiK3ZyDJaqmTwjskWBcJyMrcgrEWDnFkJwSSh7LdYE2BxBd2gY3qWe4P64iQFjAAqGoF7LfxoePQdws5N4xU6AqVK7QJ1dTMR8grgMSk9ux6vaPYq9KkrqUWc1PA4wajMXoycLydquJkAzS1WqjR8HvwuFLB3bb16CPHPtio86CdbJU95kjYt6HAKJ1hL2jWmHRgCDhaxmL7qd6U3tC3TD8bH9fWs7XLMo2AbkYXNcji5BjFJFpvBTm3s4RcrPp7eFfs5NfUShRfCxDY3he4jpHXeLusQSTdtZnKwggnWxL3qcoWQBc7SpwNKqfdgupD4vdLXY1okGemHr9LARcxgFnszQejt2wmcGprg9D6rXSG55uvyW2jaGu1ovjHiBE9Gq62a8uQmzjaBN1ihRVW3Surc5cuEa5yRUmvk5WeHyDdenkEtnNas3KDqdwPWh33FJA7Erw84gKWCSwoT7PBUpEaukU6LWVNgPkRgGT33ofw9MxiPDkhu1Xf3UeenwCc4Up7';
  //const base58Data = '9TsSUqX1Euf1kfjPg6QzPHF6EcEiYpP1oKAJqkCX7sPo8fp7kiQPdpwPjpsCwU1mthZ5gBmPrCGDXUtbBeVvBHjFmWsevauGjHu8iwmR19zGFwkqeV53P1tnYkWMQhSJwVJjK9UDXULPttMw3KkfwSHnds1yCawYjVZTfBwmwEbbnhxxUemfVonaWYvicqvj8vyPEYMATU7Z36LHMHaVztSiP9xiweuWTXxpN5ZzHRsnvVDET3RF3sLrgkEibvBFRfbVfu3yEZYwo5SzerA4qZ9mD3ZVbJ2X1gA55GzeVMqhcpPjiTswQC6w1ccNhhnDHdfKzcMnb96n5oam5Zy7vhvV7PdmvXWmHHptqHBUPGJ33A4U7UBZq4PWLJBrEHFe69QHFKtbbuN6k3NmjZyWsRwsZtW8kBM1SXzvgpHwv1ri6jJeqbKUZvebQ44NxvxogYEka1EihDPeQ7yHg8ssDSxFajrAd6VjzSRP2ZqnPXtWCwkxRK8TBMvjubzKDQyATweBTBahMgubbdwFHoqjwDSAgDH48a6qeE9vgWHegBhBYAB';
  //const event = decodeFillRelayEvent(base58Data);
  //console.log("event", event);

  //const base58Data = 'iVCwvZuhjTcy9P6qj7XRFZQMr63yyoKWL8TkRB4GKbdFpNJQ59owacC34wchTiiwgo1UEWPZfhuxuvNhC2WmcZCLspNJKmriR9Acv8Qe9VhgvibqxsHk57C7t4fGUpUG2no5RbUw9bawUJ8V1hs5LWNnwLZp6o3MzxR4cVmzitNffRzcY9iiyBMpjHbnN9gVXZZCNmReP63m21vzs';
  //const base58Data = 'iVCwvZuhjTcy9P6qj7XRFZQMr63yyoKWL8TkRB4GKbdFpNJQ59gwz168a1xzDK4BDDHHuSq6avyHXMAb82Y248a72QG178fF6SFdKmpD917kMuHAXFZJL5db3cHq1U8ENovCRr2wYAcKJ2oGsy2wTiymqEcMjxGqVGiYYkWiyYy8LZkNzC8nMoGaqCgoyCMscPJU965ZFpFaZCVyh';
  //const base58Data = '9sZ5YPsDDz9Qoo9iHV7WPhwGpFcJpDbq1WBdMerw6mgSugAudjJ645VB9LRqzSk4iEbacQKST6yU14EGRej82px4tZL9MiwX8NJ53ZVKF64nPf4Cmt55NmUy8GRNjkn8X8jQBR5X5';
  //const base58Data = 'iVCwvZuhjTcy9P6qj7XRFZQMr63yyoKWL8TkRB4GKbdFpNJQ5YpuzqQFVFyAKAfbCbSUaHKXU2ejT4vPFoCAbcsbzrAWtpSoC4TUQdpnoACtYM67PFcPT5s35gchXVvFA9oHSQJ1B47GMmfUgu4JMnxcPWJC2H3XZ7U3ps5PpSAmWJUnMvhmgYpWwvwJDNPf5bxLDfSmJK2JmTTWw';
  //const event = decodeRefundEvent(base58Data);
  //console.log("event", event);
 //processTransaction(`5D7GBZhKxhrfXWEFabeh4J3iVT1vzCVz2cnMvcgTqFwUfh7HJbuCWx2JGKM3jFMovQRt3viU1moAfZqrkyAAyMWv`);
 //processTransaction(`B7LSXrrwqKAZwkz35gRE9DFVUY4jUvc3tsJFuQyZq9vvQWeuPC8muzMvUrdqsT4Kq1kTZvNvZyQr5vbVqCaxdLV`);
 //processTransaction(`X1otekYA2frpTRaLzVVyRuy9TLAJTr8VrpNGnViTUkjVyArBYY9VwKDc3XUS9ELfMybSQbiBjEzwBAQmrSCY2x5`);
}

main2();

async function updateMyBalance() { 
  const svmWalletAddress = "CBG4RpoLqM1KJk9q3d3MeCwE9RgqeAWbwntUREPB1jUF";
  const evmWalletAddress = "0xa61164440a720bee95f3579404c415b7fbcda4379eead6fd229df27b3bf706b4";
  const solBalance = await updateSOLBalance(svmWalletAddress);
  const usdcBalance = await updateUSDCBalance(svmWalletAddress, evmWalletAddress);
}

async function updateSOLBalance(svmWalletAddress : string,) { 
  const MY_ADDRESS = new PublicKey(svmWalletAddress);
  const balance = await connection.getBalance(MY_ADDRESS);
  //logMessage(`SOL balance for ${svmWalletAddress}: ${balance}`);
  await redisClient.set(`${svmWalletAddress}_SOL_balance`, (Number(balance) * 1e9));
}


async function updateUSDCBalance(svmWalletAddress : string, evmWalletAddress : string) { 
  const USDC_MINT = new PublicKey("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
  const MY_ADDRESS = new PublicKey(svmWalletAddress);
  const ata = await getAssociatedTokenAddress(USDC_MINT, MY_ADDRESS);
  try {
    const accountInfo = await getAccount(connection, ata);
    // USDC has 6 decimals
    const balance = Number(accountInfo.amount);
    await redisClient.set(`${svmWalletAddress}_USDC_balance`, balance);
    //logMessage(`USDC balance for ${svmWalletAddress}: ${accountInfo.amount}`);


    let sql = `
      SELECT sum(expectedRefund)/1e6 as sum 
      FROM relays
      WHERE relayer = '${evmWalletAddress}'
      AND rootBundleId = 0;`

    const [rows, fields] = await dbConnection.query(sql);
    const rowDataPackets = rows as RowDataPacket[];
    const totalExpectedRefund = rowDataPackets[0].sum;
    //logMessage(`Total expected refund for ${evmWalletAddress}: ${totalExpectedRefund}`);
    await redisClient.set(`${evmWalletAddress}_expectedRefund_deployed`, totalExpectedRefund);

    // TODO: expected refund for pending bundle(s)

  } catch (e) {
    // If ATA doesn’t exist, balance is 0
  }
}


