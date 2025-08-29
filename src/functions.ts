import fs from 'fs';
import bs58 from "bs58";
import { Buffer } from "buffer";
import { ethers } from 'ethers';

const tokenConfigRaw = fs.readFileSync("../relayer/configurations/tokens.json", 'utf-8');
const tokenConfig = JSON.parse(tokenConfigRaw);

export function timeString() {
    const date = new Date();
    const hours = date.getHours().toString().padStart(2, '0');
    const minutes = date.getMinutes().toString().padStart(2, '0');
    const seconds = date.getSeconds().toString().padStart(2, '0');
    const milliseconds = date.getMilliseconds().toString().padStart(3, '0');
    return `${hours}:${minutes}:${seconds}.${milliseconds}: `;
  }
export function logMessage(message : string, color : string = "default") { 
	if(color == 'default') { 
		console.log(timeString() + message);
	} else if(color == 'green') { 
		console.log("\x1b[32m%s\x1b[0m", timeString() + message); 
	} else if(color == 'greenbold') { 
		console.log("\x1b[1m\x1b[32m%s\x1b[0m", timeString() + message); 
	} else if(color == 'yellow') { 
		console.log("\x1b[93m%s\x1b[0m", timeString() + message); 
	} else if(color == 'orange') { 
		console.log("\x1b[38;5;208m%s\x1b[0m", timeString() + message); 
	} else if(color == 'red') {
		console.log("\x1b[38;5;203;1m%s\x1b[0m", timeString() + message); 
	} else if(color == 'blue') {
		console.log("\x1b[1;36m%s\x1b[0m", timeString() + message); 
	} else if(color == 'purple') { 
		console.log("\x1b[95m%s\x1b[0m", timeString() + message); 
	} else if(color == 'gray') { 
		console.log("\x1b[90m%s\x1b[0m", timeString() + message); 
	}
}
export function slackMessage(webhookUrl : string, message : string) { 
	axios.post(webhookUrl, { text: message, username: 'Relayer' }).catch((error) => {
		// don't wait for this
	});
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

export function unwrapEventData(
  data: unknown,
  uint8ArrayKeysAsBigInt: string[] = ["depositId", "outputAmount", "inputAmount"],
  currentKey?: string
): unknown {
  // Handle null/undefined
  if (data == null) {
    return data;
  }
  // Handle BigInt
  if (typeof data === "bigint") {
    const bigIntKeysAsNumber = ["originChainId", "destinationChainId", "repaymentChainId", "chainId"];
    if (currentKey && bigIntKeysAsNumber.includes(currentKey)) {
      return Number(data);
    }
    return BigNumber.from(data);
  }
  // Handle Uint8Array and byte arrays
  if (data instanceof Uint8Array || isUint8Array(data)) {
    const bytes = data instanceof Uint8Array ? data : new Uint8Array(data as number[]);
    const hex = ethers.utils.hexlify(bytes);
    if (currentKey && uint8ArrayKeysAsBigInt.includes(currentKey)) {
      return BigNumber.from(hex);
    }
    return hex;
  }
  // Handle regular arrays (non-byte arrays)
  if (Array.isArray(data)) {
    return data.map((item) => unwrapEventData(item, uint8ArrayKeysAsBigInt));
  }
  // Handle strings (potential addresses)
  if (typeof data === "string" && isAddress(data)) {
    return ethers.utils.hexlify(bs58.decode(data));
  }
  // Handle objects
  if (typeof data === "object") {
    // Special case: if an object is in the context of the fillType key, then
    // parse out the fillType from the object
    if (currentKey === "fillType") {
      const fillType = Object.keys(data)[0];
      switch (fillType) {
        case "FastFill":
          return FillType.FastFill;
        case "ReplacedSlowFill":
          return FillType.ReplacedSlowFill;
        case "SlowFill":
          return FillType.SlowFill;
        default:
          throw new Error(`Unknown fill type: ${fillType}`);
      }
    }

    // Special case: if an object is empty, return 0x
    if (Object.keys(data).length === 0) {
      return "0x";
    }
    return Object.fromEntries(
      Object.entries(data as Record<string, unknown>).map(([key, value]) => [
        key,
        unwrapEventData(value, uint8ArrayKeysAsBigInt, key),
      ])
    );
  }
  // Return primitives as is
  return data;
}


export const hexToAddress = (hex: string) => {
	return `0x${hex.slice(2).replace(/^0+/, "").padStart(40, "0")}`;
};

export const hexToDecimal = (hex: string) => {
	return BigInt(parseInt(hex, 16)).toString();
};


// Helper to read a u64 in little-endian
function readU64LE(buffer: Buffer, offset: number, length: number = 20): { value: number; next: number } {
    //console.log("readU64LE", buffer.slice(offset, offset + length).toString("hex"));
    const value = Number(buffer.readBigUInt64LE(offset).toString());
    return { value, next: offset + length };
  }
  
  function readU64BE(buffer: Buffer, offset: number, length: number = 20): { value: bigint; next: number } {
    //console.log("readU64BE", buffer.slice(offset, offset + length).toString("hex"));
    const value = Number(hexToDecimal(buffer.slice(offset, offset + length).toString("hex")));
    return { value, next: offset + length };
  }
  
  // Helper to read a u32 in little-endian
  function readU32LE(buffer: Buffer, offset: number, length: number = 4): { value: number; next: number } {
    //console.log("readU32LE", buffer.slice(offset, offset + length).toString("hex"));
    const value = buffer.readUInt32LE(offset);
    return { value, next: offset + length };
  }


  // ====== DEPOSIT DECODER ======
export function decodeDepositEvent(base58Data: string) {
    const buffer = Buffer.from(bs58.decode(base58Data));
    let offset = 16;
  
    //console.log("buffer", buffer.toString("hex"));
  
    // inputToken
    const inputToken = buffer.slice(offset, offset + 32);
    offset += 32;
  
  
    // outputToken
    const outputToken = buffer.slice(offset, offset + 32);
    offset += 32;
  
    // inputAmount
    const inputAmountRes = readU64LE(buffer, offset);
    const inputAmount = inputAmountRes.value;
    offset = inputAmountRes.next;
  
    // outputAmount
    const outputAmountRes = readU64BE(buffer, offset);
    const outputAmount = outputAmountRes.value;
    offset = outputAmountRes.next;
  
    // destinationChainId
    const destChainRes = readU64LE(buffer, offset);
    const destinationChainId = destChainRes.value;
    offset = destChainRes.next;
  
    // depositId
    const depositIdRes = readU64BE(buffer, offset);
    const depositId = depositIdRes.value;
    offset = depositIdRes.next;
  
    // quoteTimestamp
    const quoteTimestampRes = readU32LE(buffer, offset);
    const quoteTimestamp = quoteTimestampRes.value;
    offset = quoteTimestampRes.next;
  
    // fillDeadline
    const fillDeadlineRes = readU32LE(buffer, offset);
    const fillDeadline = fillDeadlineRes.value;
    offset = fillDeadlineRes.next;
  
    // exclusivityDeadline
    const exclusivityDeadlineRes = readU32LE(buffer, offset);
    const exclusivityDeadline = exclusivityDeadlineRes.value;
    offset = exclusivityDeadlineRes.next;
  
    // depositor
    const depositor = buffer.slice(offset, offset + 32);
    offset += 32;
  
    // recipient
    const recipient = buffer.slice(offset, offset + 32);
    offset += 32;
  
    // exclusiveRelayer
    const exclusiveRelayer = buffer.slice(offset, offset + 32);
    offset += 32;
  
    // message
    // for the message, we need to read the remaining bytes 
    let message = '0x' + buffer.slice(offset).toString("hex");
    if(message == '0x00000000') { 
      message = '0x';
    }
    
    let tokenName = findOriginToken(34268394551451, '0x' + inputToken.toString("hex"));
    let outputTokenName = findOriginToken(destinationChainId, hexToAddress('0x' + outputToken.toString("hex")));
    let depositKey = `${depositId}_${tokenName}_34268394551451_${destinationChainId}_${inputAmount}`;
  
    return {
      inputToken: '0x' + inputToken.toString("hex"),
      outputToken: hexToAddress('0x' + outputToken.toString("hex")),
      inputAmount: inputAmount,
      outputAmount: outputAmount,
      destinationChainId: destinationChainId,
      originChainId: 34268394551451,
      depositId: depositId,
      quoteTimestamp: quoteTimestamp,
      fillDeadline: fillDeadline,
      exclusivityDeadline: exclusivityDeadline,
      depositor: '0x' + depositor.toString("hex"),
      recipient: hexToAddress('0x' + recipient.toString("hex")),
      exclusiveRelayer: hexToAddress('0x' + exclusiveRelayer.toString("hex")),
      message: message,
      depositKey: depositKey,
      tokenName: tokenName,
      outputTokenName: outputTokenName,
    };
  }
  
  // ====== FILLRELAY DECODER ======
  export function decodeFillRelayEvent(base58Data: string) { 
    const buffer = Buffer.from(bs58.decode(base58Data));
    let offset = 16;
  
    //console.log("buffer", buffer.toString("hex"));
  
    // inputToken
    const inputToken = buffer.slice(offset, offset + 32);
    offset += 32;
  
    // outputToken
    const outputToken = buffer.slice(offset, offset + 32);
    offset += 44;
    
  
    // inputAmount
    const inputAmountRes = readU64BE(buffer, offset);
    //console.log("inputAmount: ", buffer.slice(offset, offset + 20).toString("hex"));
    const inputAmount = inputAmountRes.value;
    offset = inputAmountRes.next;
  
  
    // outputAmount
    const outputAmountRes = readU64LE(buffer, offset, 8);
    //console.log("outputAmount: ", buffer.slice(offset, offset + 8).toString("hex"));
    const outputAmount = outputAmountRes.value;
    offset = outputAmountRes.next;
  
    // repaymentChainId
    const repaymentChainIdRes = readU64LE(buffer, offset, 8);
    //console.log("repaymentChainId: ", buffer.slice(offset, offset + 8).toString("hex"));
    const repaymentChainId = repaymentChainIdRes.value;
    offset = repaymentChainIdRes.next;
  
    // originChainId
    const originChainIdRes = readU64LE(buffer, offset, 8);
    //console.log("originChainId: ", buffer.slice(offset, offset + 8).toString("hex"));
    const originChainId = originChainIdRes.value;
    offset = originChainIdRes.next;
    
    // depositId
    const depositIdRes = readU64BE(buffer, offset, 32);
    //console.log("depositId: ", buffer.slice(offset, offset + 4).toString("hex"));
    const depositId = depositIdRes.value;
    offset = depositIdRes.next;
  
    // fillDeadline
    const fillDeadlineRes = readU32LE(buffer, offset);
    const fillDeadline = fillDeadlineRes.value;
    offset = fillDeadlineRes.next;
  
    // exclusivityDeadline
    const exclusivityDeadlineRes = readU32LE(buffer, offset);
    const exclusivityDeadline = exclusivityDeadlineRes.value;
    offset = exclusivityDeadlineRes.next;
  
    // exclusiveRelayer
    const exclusiveRelayer = buffer.slice(offset, offset + 32);
    offset += 32;
  
    // relayer
    const relayer = buffer.slice(offset, offset + 32);
    offset += 32;
  
    // depositor
    const depositor = buffer.slice(offset, offset + 32);
    offset += 32;
  
    // recipient
    const recipient = buffer.slice(offset, offset + 32);
    offset += 32;
  
    let messageHash = '0x' + buffer.slice(offset, offset + 32).toString("hex");
  
  
    const evmTokenAddr = hexToAddress("0x" + inputToken.toString("hex"));
    let tokenName = findOriginToken(originChainId, evmTokenAddr);
    let outputTokenName = findOriginToken(34268394551451, '0x' + outputToken.toString("hex"));
    let depositKey = `${depositId}_${tokenName}_${repaymentChainId}_34268394551451_${inputAmount}`;
  
    let relayerAddress = '0x' + relayer.toString("hex");
    if(Number(repaymentChainId) != 34268394551451) { 
      relayerAddress = hexToAddress(relayerAddress);
    }
    let exclusiveRelayerAddress = '0x' + exclusiveRelayer.toString("hex");
    if(exclusiveRelayerAddress != '0x0000000000000000000000000000000000000000000000000000000000000000') { 
      exclusiveRelayerAddress = '0x0000000000000000000000000000000000000000';
    }
  
    return {
      inputToken: hexToAddress('0x' + inputToken.toString("hex")),
      outputToken: '0x' + outputToken.toString("hex"),
      inputAmount: inputAmount,
      outputAmount: outputAmount,
      repaymentChainId: repaymentChainId,
      originChainId: originChainId,
      destinationChainId: 34268394551451,
      depositId: depositId,
      fillDeadline: fillDeadline,
      exclusivityDeadline: exclusivityDeadline,
      exclusiveRelayer: exclusiveRelayerAddress,
      relayer: relayerAddress,
      depositor: hexToAddress('0x' + depositor.toString("hex")),
      recipient: '0x' + recipient.toString("hex"),
      messageHash: messageHash,
      depositKey: depositKey,
      tokenName: tokenName,
      outputTokenName: outputTokenName,
    };
  }
  
  // ====== REFUND DECODER ======
  export function decodeRefundEvent(base58Data: string) { 
    const buffer = Buffer.from(bs58.decode(base58Data));
    let offset = 16;
  
    //console.log("buffer", buffer.toString("hex"));
    
    const eventString = buffer.toString("hex").substring(0, 32);

    if(eventString.indexOf("e445a52e51cb9a1dc6a7f8af220304f0") > -1) { 
      
      // amount To Return
      const amountToReturnRes = readU64LE(buffer, offset, 8);
      //console.log("amountToReturn: ", buffer.slice(offset, offset + 8).toString("hex"));
      const amountToReturn = amountToReturnRes.value;
      offset = amountToReturnRes.next;
    
      // refundChainId
      const refundChainIdRes = readU64LE(buffer, offset, 8);
      //console.log("refundChainId: ", buffer.slice(offset, offset + 8).toString("hex"));
      const refundChainId = refundChainIdRes.value;
      offset = refundChainIdRes.next;
    
      const refundAmountsLenRes = readU32LE(buffer, offset);
      const refundAmountsLen = refundAmountsLenRes.value;
      offset = refundAmountsLenRes.next;
    
      //console.log("refundAmountsLen: ", refundAmountsLen);
    
      const refundAmounts = [];
      if(refundAmountsLen > 0) { 
        for(let i = 0; i < refundAmountsLen; i++) { 
          const refundAmountRes = readU64LE(buffer, offset, 8);
          const refundAmount = refundAmountRes.value;
          offset = refundAmountRes.next;  
          //console.log("refundAmount: ", refundAmount);
          refundAmounts.push(refundAmount);
        }
      }
    
      // rootBundleId (u32)
      const rootBundleIdRes = readU32LE(buffer, offset);
      const rootBundleId = rootBundleIdRes.value;
      offset = rootBundleIdRes.next;
    
      // leafId (u32)
      const leafIdRes = readU32LE(buffer, offset);
      const leafId = leafIdRes.value;
      offset = leafIdRes.next;
    
      // l2TokenAddress
      const l2TokenAddress = buffer.slice(offset, offset + 32);
      offset += 32;
    
      // refundAddresses
      const refundAddressesLenRes = readU32LE(buffer, offset);
      const refundAddressesLen = refundAddressesLenRes.value;
      offset = refundAddressesLenRes.next;
    
      const refundAddresses = [];

      if(refundAddressesLen > 0) { 
        for(let i = 0; i < refundAddressesLen; i++) { 
          const refundAddress = buffer.slice(offset, offset + 32);
          offset += 32;
          refundAddresses.push('0x' + refundAddress.toString("hex"));
        }
      }
    
      // deferredRefunds (1 byte)
      const deferredRefunds = buffer.readUInt8(offset) !== 0;
      offset += 1;
    
      // caller (32 bytes)
      const callerRes = buffer.slice(offset, offset + 32);
      const caller = "0x" + callerRes.toString("hex");
      offset += 32;
    
      let tokenName = findOriginToken(refundChainId, '0x' + l2TokenAddress.toString("hex"));
    
      if(refundAmounts.length > 0) { 
        return { 
          amountToReturn: amountToReturn,
          refundChainId: refundChainId,
          refundAmounts: refundAmounts,
          rootBundleId: rootBundleId,
          leafId: leafId,
          l2TokenAddress: '0x' + l2TokenAddress.toString("hex"),
          refundAddresses: refundAddresses,
          deferredRefunds: deferredRefunds,
          caller: caller,
          tokenName: tokenName,
        }
      } else {
        // missing data, return null;
        return null;
      }
    } else {
      // missing data, return null;
      //console.log("missing data");
      return null;
    }
  
  }